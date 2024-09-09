import { Hono } from "https://deno.land/x/hono@v4.3.11/mod.ts";
import { html } from "https://deno.land/x/hono@v4.3.11/helper/html/index.ts";
import { WasmOAuthClient } from "./pkg/oauth_wasm.js";

const URL_BASE = Deno.env.get("URL_BASE") || "http://localhost";
const CALLBACK_PATH = "/callback";
const CLIENT_METADATA_PATH = "/client-metadata.json";
const JWKS_PATH = "/.well-known/jwks.json";

const client = new WasmOAuthClient({
  metadata: {
    client_id: URL_BASE + CLIENT_METADATA_PATH,
    client_uri: URL_BASE,
    redirect_uris: [URL_BASE + CALLBACK_PATH],
    token_endpoint_auth_method: "private_key_jwt",
    grant_types: ["authorization_code"],
    scopes: ["atproto"],
    jwks_uri: URL_BASE + JWKS_PATH,
    token_endpoint_auth_signing_alg: "ES256",
  },
  keys: [Deno.env.get("PRIVATE_KEY_1")],
  doh_service_url: Deno.env.get("DOH_SERVICE_URL"),
});

const app = new Hono();

app.get("/", (c) => {
  return c.html(html`<!DOCTYPE html>
    <html>
      <h2>
        ATProto OAuth with
        <a href="https://github.com/sugyan/atrium/pull/219">ATrium</a>
      </h2>
      <p>Running <code>atrium-oauth-client</code> on Deno Deploy with WASM.</p>
      <h2>Sign In</h2>
      <form action="/signin">
        <input type="text" name="input" placeholder="Your Handle" />
        <button type="submit">Sign In</button>
      </form>
      <br />
      or
      <a href="/signin">Sign In with <code>bsky.social</code></a>
      <h2>Resources</h2>
      <ul>
        <li><a href="/client-metadata.json">Client Metadata</a></li>
        <li><a href="/.well-known/jwks.json">JWKS</a></li>
        <li>
          <a href="https://github.com/sugyan/atrium-oauth-wasm">Source Code</a>
        </li>
      </ul>
    </html>`);
});
app.get("/signin", async (c) => {
  const input = c.req.query("input") || "https://bsky.social";
  try {
    return c.redirect(await client.authorize(input));
  } catch (e) {
    return c.json({ error: e });
  }
});
app.get(CALLBACK_PATH, async (c) => {
  const query = c.req.query();
  try {
    const tokenSet = await client.callback(query);
    return c.json(tokenSet);
  } catch (e) {
    return c.json({ error: e });
  }
});
app.get(CLIENT_METADATA_PATH, (c) => {
  return c.json(client.client_metadata());
});
app.get(JWKS_PATH, (c) => {
  return c.json(client.jwks());
});

Deno.serve({ port: 8765 }, app.fetch);
