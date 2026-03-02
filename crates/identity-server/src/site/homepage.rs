use axum::response::{Html, IntoResponse};

use super::components;
use super::css;

pub async fn homepage() -> impl IntoResponse {
    let nav = components::nav_bar();
    let terminal = components::terminal_window();
    let footer = components::footer();

    let html = format!(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>botnet.pub &mdash; Verifiable Identities for AI Agents</title>
    {fonts}
    <style>
{tokens}
{reset}
{homepage}
    </style>
  </head>
  <body>
    {nav}

    <div class="page">

      <!-- ====== Hero ====== -->
      <section class="hero">
        <div class="hero-text">
          <h1>Verifiable identities for <em>autonomous AI agents.</em></h1>
          <p class="lede">Cryptographically-bound bot identities with signed records, policy-governed key management, and cross-bot attestations. No bearer tokens, no shared secrets.</p>
          <div class="hero-actions">
            <a class="btn btn-primary" href="/docs">Get Started</a>
            <a class="btn" href="/docs/protocol">Read the Protocol</a>
          </div>
          <div class="install-cmd">
            <span class="prompt">$</span>
            <code>curl -fsSL https://botnet.pub/install.sh | sh</code>
            <button class="copy-btn" onclick="navigator.clipboard.writeText('curl -fsSL https://botnet.pub/install.sh | sh').then(()=>{{this.textContent='copied!';setTimeout(()=>this.textContent='copy',1500)}})">copy</button>
          </div>
        </div>
        {terminal}
      </section>

      <!-- ====== Why botnet? ====== -->
      <section style="margin-top:4rem">
        <h2 class="section-heading">Why botnet?</h2>
        <p class="section-sub">AI agents are proliferating &mdash; sending emails, writing code, managing infrastructure, talking to each other. But there is no standard way to answer basic questions about them.</p>
        <div class="grid-2x2" style="margin-top:1.5rem">
          <div class="card">
            <div class="card-icon">?</div>
            <h3>Who operates this bot?</h3>
            <p>No verifiable link between a bot and its owner. Anyone can claim to run any agent.</p>
          </div>
          <div class="card">
            <div class="card-icon">?</div>
            <h3>Is this bot still active?</h3>
            <p>No lifecycle management or revocation. Decommissioned bots remain indistinguishable from live ones.</p>
          </div>
          <div class="card">
            <div class="card-icon">?</div>
            <h3>Can it do what it claims?</h3>
            <p>No capability declarations or third-party attestations. Trust is implicit, not verifiable.</p>
          </div>
          <div class="card">
            <div class="card-icon">?</div>
            <h3>Who authorized this action?</h3>
            <p>No cryptographic proof chain. Actions happen without auditable authorization trails.</p>
          </div>
        </div>
      </section>

      <!-- ====== Core Concepts ====== -->
      <section style="margin-top:4rem">
        <h2 class="section-heading">Core Concepts</h2>
        <p class="section-sub">Six building blocks for verifiable bot identity.</p>
        <div class="grid-3x2" style="margin-top:1.5rem">
          <div class="card">
            <div class="card-icon">#</div>
            <h3>Bot ID</h3>
            <p>A deterministic identifier derived from a public key: <code>urn:bot:sha256:{{hex}}</code>. Same key, same ID. No central authority.</p>
          </div>
          <div class="card">
            <div class="card-icon">&curren;</div>
            <h3>Bot Record</h3>
            <p>The identity document: public keys, owner info, capabilities, endpoints, controllers, and lifecycle status.</p>
          </div>
          <div class="card">
            <div class="card-icon">&check;</div>
            <h3>Proof</h3>
            <p>Every mutation includes a JWS signature over JCS-canonicalized payload. Ed25519 verified before any change.</p>
          </div>
          <div class="card">
            <div class="card-icon">&amp;</div>
            <h3>Policy</h3>
            <p>Optional m-of-n threshold rules per operation. Require 2-of-3 signers to rotate a key or 3-of-5 to revoke.</p>
          </div>
          <div class="card">
            <div class="card-icon">&starf;</div>
            <h3>Attestation</h3>
            <p>A signed statement one bot makes about another. First-class objects with issuer verification and expiration.</p>
          </div>
          <div class="card">
            <div class="card-icon">&rArr;</div>
            <h3>Controller</h3>
            <p>Bot-to-bot delegation. A controller bot can manage keys or updates for another, enabling hierarchical trust.</p>
          </div>
        </div>
      </section>

      <!-- ====== How It Works ====== -->
      <section style="margin-top:4rem">
        <h2 class="section-heading">How It Works</h2>
        <p class="section-sub">From key generation to attestation in four steps.</p>
        <div class="steps" style="margin-top:1.5rem">
          <div class="step">
            <div class="step-num">1</div>
            <h3>Generate Key</h3>
            <p>Create an Ed25519 keypair. The public key determines your Bot ID.</p>
            <pre>SEED=$(openssl rand -hex 32)</pre>
          </div>
          <div class="step">
            <div class="step-num">2</div>
            <h3>Register Bot</h3>
            <p>Submit a signed bot record to the registry with your identity details.</p>
            <pre>botnet register bot.json</pre>
          </div>
          <div class="step">
            <div class="step-num">3</div>
            <h3>Manage Identity</h3>
            <p>Add keys, update fields, set policies, delegate control &mdash; all signed.</p>
            <pre>botnet add-key &lt;id&gt; key.json</pre>
          </div>
          <div class="step">
            <div class="step-num">4</div>
            <h3>Attest &amp; Delegate</h3>
            <p>Publish attestations about other bots or delegate control to trusted agents.</p>
            <pre>botnet publish-attestation ...</pre>
          </div>
        </div>
      </section>

      <!-- ====== API Quick Reference ====== -->
      <section style="margin-top:4rem">
        <h2 class="section-heading">API Quick Reference</h2>
        <p class="section-sub">All endpoints at <code>https://botnet.pub/v1</code>. <a href="/docs/api" style="color:var(--cyan);text-decoration:none">Full reference &rarr;</a></p>
        <div style="margin-top:1rem;border:1px solid var(--line);border-radius:12px;overflow:hidden">
          <table class="api-table">
            <thead><tr><th>Method</th><th>Endpoint</th><th>Auth</th><th>Description</th></tr></thead>
            <tbody>
              <tr><td><code class="method-post">POST</code></td><td><code>/v1/bots</code></td><td>proof</td><td>Register a new bot</td></tr>
              <tr><td><code class="method-get">GET</code></td><td><code>/v1/bots/{{bot_id}}</code></td><td>&mdash;</td><td>Fetch a bot record</td></tr>
              <tr><td><code class="method-patch">PATCH</code></td><td><code>/v1/bots/{{bot_id}}</code></td><td>proof</td><td>Update a bot record</td></tr>
              <tr><td><code class="method-post">POST</code></td><td><code>/v1/bots/{{bot_id}}/keys</code></td><td>proof</td><td>Add a public key</td></tr>
              <tr><td><code class="method-delete">DELETE</code></td><td><code>/v1/bots/{{bot_id}}/keys/{{key_id}}</code></td><td>proof</td><td>Revoke a key</td></tr>
              <tr><td><code class="method-post">POST</code></td><td><code>/v1/bots/{{bot_id}}/keys/rotate</code></td><td>proof</td><td>Rotate a key</td></tr>
              <tr><td><code class="method-post">POST</code></td><td><code>/v1/bots/{{bot_id}}/revoke</code></td><td>proof</td><td>Revoke a bot</td></tr>
              <tr><td><code class="method-post">POST</code></td><td><code>/v1/attestations</code></td><td>signature</td><td>Publish an attestation</td></tr>
              <tr><td><code class="method-get">GET</code></td><td><code>/v1/search</code></td><td>&mdash;</td><td>Search bots</td></tr>
              <tr><td><code class="method-get">GET</code></td><td><code>/v1/nonce</code></td><td>&mdash;</td><td>Get anti-replay nonce</td></tr>
              <tr><td><code class="method-get">GET</code></td><td><code>/v1/stats</code></td><td>&mdash;</td><td>Registry statistics</td></tr>
            </tbody>
          </table>
        </div>
      </section>

    </div>

    {footer}
    {stats_js}
    {copy_js}
  </body>
</html>"##,
        fonts = css::FONT_IMPORTS,
        tokens = css::DESIGN_TOKENS,
        reset = css::RESET,
        homepage = css::HOMEPAGE_CSS,
        nav = nav,
        terminal = terminal,
        footer = footer,
        stats_js = components::STATS_JS,
        copy_js = components::COPY_JS,
    );

    Html(html)
}
