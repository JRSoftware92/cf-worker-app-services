/**
 * /secure            -> HTML: "<email> authenticated at <timestamp> from <country-link>"
 * /secure/<COUNTRY>  -> the country's flag image, read from a private R2 bucket
 *
 * Identity comes from the Cloudflare Access JWT (Cf-Access-Jwt-Assertion),
 * which this Worker verifies itself (signature, issuer, audience, expiry).
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ---------- JWT helpers ----------

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

function decodePart(part) {
  return JSON.parse(decoder.decode(b64urlToBytes(part)));
}

let jwksCache = { keys: null, expires: 0 };

async function getJwks(env, forceRefresh = false) {
  if (!forceRefresh && jwksCache.keys && Date.now() < jwksCache.expires) {
    return jwksCache.keys;
  }
  const res = await fetch(`${env.TEAM_DOMAIN}/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error(`Failed to fetch Access certs: ${res.status}`);
  const { keys } = await res.json();
  jwksCache = { keys, expires: Date.now() + 60 * 60 * 1000 };
  return keys;
}

async function verifyAccessJwt(token, env) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Malformed token");

  const header = decodePart(parts[0]);
  const payload = decodePart(parts[1]);
  if (header.alg !== "RS256") throw new Error("Unexpected algorithm");

  // Find the signing key; refresh once in case keys were rotated.
  let keys = await getJwks(env);
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    keys = await getJwks(env, true);
    jwk = keys.find((k) => k.kid === header.kid);
  }
  if (!jwk) throw new Error("Unknown signing key");

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlToBytes(parts[2]),
    encoder.encode(`${parts[0]}.${parts[1]}`)
  );
  if (!valid) throw new Error("Bad signature");

  const now = Math.floor(Date.now() / 1000);
  const audOk = Array.isArray(payload.aud)
    ? payload.aud.includes(env.POLICY_AUD)
    : payload.aud === env.POLICY_AUD;
  if (!audOk) throw new Error("Audience mismatch");
  if (payload.iss !== env.TEAM_DOMAIN) throw new Error("Issuer mismatch");
  if (typeof payload.exp !== "number" || payload.exp < now) throw new Error("Token expired");
  if (typeof payload.nbf === "number" && payload.nbf > now) throw new Error("Token not yet valid");

  return payload;
}

// ---------- Response helpers ----------

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};

function text(status, body) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", ...securityHeaders },
  });
}

// ---------- Worker ----------

export default {
  async fetch(request, env) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return text(405, "Method Not Allowed");
    }

    // 1. Authenticate: require and verify the Access JWT.
    const token = request.headers.get("Cf-Access-Jwt-Assertion");
    if (!token) return text(401, "Unauthorized");

    let identity;
    try {
      identity = await verifyAccessJwt(token, env);
    } catch (err) {
      console.error("JWT verification failed:", err.message);
      return text(403, "Forbidden");
    }

    // 2. Route.
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, ""); // tolerate trailing slash

    if (path === "/secure") {
      return handleIdentityPage(request, identity);
    }

    const match = path.match(/^\/secure\/([A-Za-z]{2})$/);
    if (match) {
      return handleFlag(match[1], env);
    }

    return text(404, "Not Found");
  },
};

// ---------- Handlers ----------

function handleIdentityPage(request, identity) {
  const email = identity.email ?? identity.common_name ?? "unknown user"; // common_name = service token
  // JWT "iat" is when Access issued the token, i.e. when the user authenticated.
  // To show the current request time instead, use: new Date().toISOString()
  const timestamp = new Date((identity.iat ?? Date.now() / 1000) * 1000).toISOString();

  const country = request.cf?.country; // two-letter ISO code, e.g. "US"
  const countryHtml =
    country && /^[A-Za-z]{2}$/.test(country) && country !== "XX" && country !== "T1"
      ? `<a href="/secure/${encodeURIComponent(country)}">${escapeHtml(country)}</a>`
      : "an unknown location";

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure</title>
</head>
<body>
  <p>${escapeHtml(email)} authenticated at ${escapeHtml(timestamp)} from ${countryHtml}</p>
</body>
</html>`;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "private, no-store",
      ...securityHeaders,
    },
  });
}

async function handleFlag(code, env) {
  const key = `flags/${code.toLowerCase()}.png`;
  const object = await env.FLAGS.get(key);
  if (!object) return text(404, "Flag not found");

  const headers = new Headers(securityHeaders);
  object.writeHttpMetadata(headers); // sets Content-Type stored with the object
  if (!headers.has("Content-Type")) headers.set("Content-Type", "image/png");
  headers.set("ETag", object.httpEtag);
  headers.set("Cache-Control", "private, max-age=86400");

  return new Response(object.body, { headers });
}
