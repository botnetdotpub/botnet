use axum::response::{Html, IntoResponse};
use identity_cli::{generate_cli_docs, CliCommandDoc};
use serde_json::Value;
use utoipa::OpenApi;

use super::components;
use super::css;
use super::util::*;
use crate::ApiDoc;

// ---------------------------------------------------------------------------
// Model types
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ApiDocsModel {
    endpoints: Vec<ApiEndpointDoc>,
    schemas: Vec<ApiSchemaDoc>,
}

#[derive(Debug)]
struct ApiEndpointDoc {
    method: String,
    path: String,
    summary: String,
    description: Option<String>,
    operation_id: Option<String>,
    auth: String,
    parameters: Vec<ApiParameterDoc>,
    request_body: Option<String>,
    responses: Vec<ApiResponseDoc>,
}

#[derive(Debug)]
struct ApiParameterDoc {
    name: String,
    location: String,
    required: bool,
    schema: String,
    description: Option<String>,
}

#[derive(Debug)]
struct ApiResponseDoc {
    status: String,
    description: Option<String>,
}

#[derive(Debug)]
struct ApiSchemaDoc {
    name: String,
    kind: String,
    required_fields: usize,
    property_count: usize,
}

#[derive(Clone, Copy)]
struct CliCommandGuide {
    purpose: &'static str,
    input_file: &'static str,
    example: &'static str,
}

// ---------------------------------------------------------------------------
// Docs shell layout
// ---------------------------------------------------------------------------

struct DocsShellArgs<'a> {
    page_title: &'a str,
    page_subtitle: &'a str,
    breadcrumb: &'a str,
    sidebar_html: &'a str,
    content_html: &'a str,
    toc_html: &'a str,
    active_tab: &'a str,
}

fn docs_shell(args: DocsShellArgs<'_>) -> Html<String> {
    let tab = |name: &str, href: &str| -> String {
        let cls = if args.active_tab == name {
            "active"
        } else {
            ""
        };
        format!(r#"<a href="{href}" class="{cls}">{name}</a>"#)
    };

    let html = format!(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>botnet.pub docs &mdash; {title}</title>
    {fonts}
    <style>
{tokens}
{reset}
{docs_css}
    </style>
  </head>
  <body>
    <header class="topbar">
      <a href="/" class="brand"><span>$</span> botnet.pub</a>
      <nav class="tabs">
        {tab_overview}
        {tab_protocol}
        {tab_api}
        {tab_cli}
      </nav>
    </header>
    <main class="layout">
      <aside class="sidebar">{sidebar}</aside>
      <section class="content">
        <div class="breadcrumbs">
          <a href="/">Home</a> <span class="sep">/</span>
          <a href="/docs">Docs</a> <span class="sep">/</span>
          <span>{breadcrumb}</span>
        </div>
        <div class="headline">
          <h1>{title}</h1>
          <p>{subtitle}</p>
        </div>
        {content}
      </section>
      <aside class="toc">
        <h3>On This Page</h3>
        <nav>{toc}</nav>
      </aside>
    </main>
    {copy_js}
    {toc_js}
  </body>
</html>"##,
        title = args.page_title,
        fonts = css::FONT_IMPORTS,
        tokens = css::DESIGN_TOKENS,
        reset = css::RESET,
        docs_css = css::DOCS_CSS,
        tab_overview = tab("Overview", "/docs"),
        tab_protocol = tab("Protocol", "/docs/protocol"),
        tab_api = tab("API", "/docs/api"),
        tab_cli = tab("CLI", "/docs/cli"),
        sidebar = args.sidebar_html,
        breadcrumb = args.breadcrumb,
        subtitle = args.page_subtitle,
        content = args.content_html,
        toc = args.toc_html,
        copy_js = components::COPY_JS,
        toc_js = components::TOC_JS,
    );
    Html(html)
}

fn code_block(code: &str) -> String {
    format!(
        r#"<div class="code-block"><button class="copy-btn">copy</button><pre><code>{}</code></pre></div>"#,
        escape_html(code)
    )
}

// ---------------------------------------------------------------------------
// Sidebar builders
// ---------------------------------------------------------------------------

fn sidebar_section(title: &str, links: &[(&str, &str, bool)], open: bool) -> String {
    let open_attr = if open { " open" } else { "" };
    let mut link_html = String::new();
    for (href, label, active) in links {
        let cls = if *active { " active" } else { "" };
        link_html.push_str(&format!(
            r##"<a href="{href}" class="side-link{cls}">{label}</a>"##
        ));
    }
    format!(r##"<details{open_attr}><summary>{title}</summary>{link_html}</details>"##)
}

// ---------------------------------------------------------------------------
// Docs Index
// ---------------------------------------------------------------------------

pub async fn docs_index() -> impl IntoResponse {
    let api_docs = build_api_docs_model();
    let cli_docs = generate_cli_docs();
    let command_count = count_cli_commands(&cli_docs.commands);

    let sidebar_html = [
        sidebar_section(
            "Getting Started",
            &[
                ("/docs", "Overview", true),
                ("/docs/protocol", "Protocol", false),
                ("/docs/api", "API Reference", false),
                ("/docs/cli", "CLI Reference", false),
            ],
            true,
        ),
        sidebar_section(
            "Resources",
            &[
                ("/openapi.json", "OpenAPI Spec", false),
                ("/swagger", "Swagger UI", false),
                ("/install.sh", "Install Script", false),
            ],
            true,
        ),
    ]
    .join("\n");

    let content_html = format!(
        r##"
        <section id="welcome" class="doc-section">
          <h1>Documentation</h1>
          <p>Botnet gives every AI agent a cryptographically-bound identity &mdash; a deterministic ID derived from its public key, a signed record in a public registry, and a policy engine that governs who can act on its behalf.</p>
          <p>Docs are generated from Rust source-of-truth metadata: HTTP endpoints and schemas from <code>utoipa</code> OpenAPI generation, and CLI commands from Clap command definitions.</p>
        </section>
        <section id="coverage" class="doc-section">
          <h2>Generated Coverage</h2>
          <table>
            <thead><tr><th>Surface</th><th>Source</th><th>Coverage</th></tr></thead>
            <tbody>
              <tr><td>API</td><td><code>ApiDoc::openapi()</code></td><td>{} endpoints / {} schemas</td></tr>
              <tr><td>CLI</td><td><code>Cli::command()</code></td><td>{} commands</td></tr>
            </tbody>
          </table>
        </section>
        <section id="quickstart" class="doc-section">
          <h2>Quickstart</h2>
          <p>Install the CLI and query the registry in under a minute.</p>
          {}
        </section>
        <section id="choose-path" class="doc-section">
          <h2>Choose Your Path</h2>
          <div class="doc-grid">
            <article class="mini-card">
              <h3>Protocol</h3>
              <p>Bot ID derivation, record schema, proof model, policy engine, controllers, and attestations.</p>
              <a href="/docs/protocol">Read Protocol Spec &rarr;</a>
            </article>
            <article class="mini-card">
              <h3>API Reference</h3>
              <p>Endpoint contracts, auth requirements, request/response schemas, and route-level details.</p>
              <a href="/docs/api">Open API Reference &rarr;</a>
            </article>
            <article class="mini-card">
              <h3>CLI Reference</h3>
              <p>Global flags, command catalog, and generated help output for every CLI command.</p>
              <a href="/docs/cli">Open CLI Reference &rarr;</a>
            </article>
          </div>
        </section>
        "##,
        api_docs.endpoints.len(),
        api_docs.schemas.len(),
        command_count,
        code_block("curl -fsSL https://botnet.pub/install.sh | sh\nbotnet --base-url https://botnet.pub/v1 search --limit 5"),
    );

    let toc_html = r##"
        <a href="#welcome">Welcome</a>
        <a href="#coverage">Coverage</a>
        <a href="#quickstart">Quickstart</a>
        <a href="#choose-path">Choose Path</a>
    "##;

    docs_shell(DocsShellArgs {
        page_title: "Documentation",
        page_subtitle: "Generated from Rust handlers, schemas, and command definitions.",
        breadcrumb: "Overview",
        sidebar_html: &sidebar_html,
        content_html: &content_html,
        toc_html,
        active_tab: "Overview",
    })
}

// ---------------------------------------------------------------------------
// Protocol Page
// ---------------------------------------------------------------------------

pub async fn docs_protocol() -> impl IntoResponse {
    let sidebar_html = [
        sidebar_section(
            "Getting Started",
            &[
                ("/docs", "Overview", false),
                ("/docs/protocol", "Protocol", true),
                ("/docs/api", "API Reference", false),
                ("/docs/cli", "CLI Reference", false),
            ],
            true,
        ),
        sidebar_section(
            "Protocol Sections",
            &[
                ("#bot-id", "Bot ID", false),
                ("#bot-record", "Bot Record", false),
                ("#proof-model", "Proof Model", false),
                ("#policy-engine", "Policy Engine", false),
                ("#controllers", "Controllers", false),
                ("#attestations", "Attestations", false),
                ("#auth-flow", "Auth Flow", false),
            ],
            true,
        ),
    ]
    .join("\n");

    let content_html = format!(
        r##"
        <section id="bot-id" class="doc-section">
          <h1>Protocol Specification</h1>
          <h2>Bot ID</h2>
          <p>A Bot ID is a deterministic identifier derived from a public key:</p>
          {bot_id_code}
          <p>The same Ed25519 public key always produces the same Bot ID. No central authority assigns them &mdash; identity is derived from cryptographic material alone.</p>
          <p>The <code>pk</code> bytes are the raw 32-byte Ed25519 public key (not multibase-encoded). The SHA-256 hash is hex-encoded (lowercase, 64 characters).</p>
        </section>

        <section id="bot-record" class="doc-section">
          <h2>Bot Record</h2>
          <p>The identity document for a bot. A Bot Record contains:</p>
          <table>
            <thead><tr><th>Field</th><th>Type</th><th>Description</th></tr></thead>
            <tbody>
              <tr><td><code>bot_id</code></td><td>string</td><td>Server-assigned URN identifier</td></tr>
              <tr><td><code>version</code></td><td>integer</td><td>Monotonically incrementing version</td></tr>
              <tr><td><code>status</code></td><td>enum</td><td><code>active</code>, <code>deprecated</code>, or <code>revoked</code></td></tr>
              <tr><td><code>display_name</code></td><td>string?</td><td>Human-readable name</td></tr>
              <tr><td><code>description</code></td><td>string?</td><td>Purpose/description</td></tr>
              <tr><td><code>owner</code></td><td>object?</td><td>Owner metadata (name, contact, org)</td></tr>
              <tr><td><code>public_keys</code></td><td>array</td><td>Ed25519 public keys with purpose, revocation status</td></tr>
              <tr><td><code>endpoints</code></td><td>array?</td><td>Service endpoints (URL, protocol, description)</td></tr>
              <tr><td><code>capabilities</code></td><td>array?</td><td>Declared capabilities (e.g. <code>calendar.read</code>)</td></tr>
              <tr><td><code>controllers</code></td><td>array?</td><td>Delegated controller bots with permissions</td></tr>
              <tr><td><code>policy</code></td><td>object?</td><td>m-of-n threshold rules per operation</td></tr>
              <tr><td><code>attestations</code></td><td>array?</td><td>Third-party attestations received</td></tr>
            </tbody>
          </table>
          <p>The <code>bot_id</code>, <code>version</code>, <code>created_at</code>, and <code>updated_at</code> fields are server-managed. All other fields are client-provided and signed.</p>
        </section>

        <section id="proof-model" class="doc-section">
          <h2>Proof Model</h2>
          <p>Every mutation (register, update, revoke, key rotation) must include a cryptographic proof. The proof is a JWS (JSON Web Signature) over the JCS-canonicalized request payload.</p>
          <h3>Signature Process</h3>
          <ol>
            <li>Build the request payload as JSON (without proof fields)</li>
            <li>Canonicalize the payload using JCS (RFC 8785)</li>
            <li>Sign the canonical bytes with Ed25519</li>
            <li>Encode as a compact JWS (detached payload)</li>
            <li>Attach as <code>proof</code> field in the request</li>
          </ol>
          <h3>Single Signature</h3>
          {single_proof_code}
          <h3>Multi-Signature (proof_set)</h3>
          <p>For operations requiring m-of-n approval, provide a <code>proof_set</code> array instead:</p>
          {multi_proof_code}
        </section>

        <section id="policy-engine" class="doc-section">
          <h2>Policy Engine</h2>
          <p>Bots can define threshold policies per operation type. A policy specifies how many signers are required and from which set of keys.</p>
          <h3>Operation Types</h3>
          <table>
            <thead><tr><th>Operation</th><th>Description</th></tr></thead>
            <tbody>
              <tr><td><code>update</code></td><td>Update mutable record fields</td></tr>
              <tr><td><code>add_key</code></td><td>Add a new public key</td></tr>
              <tr><td><code>revoke_key</code></td><td>Revoke an existing key</td></tr>
              <tr><td><code>rotate_key</code></td><td>Atomic key rotation (revoke + add)</td></tr>
              <tr><td><code>revoke_bot</code></td><td>Revoke the entire identity</td></tr>
            </tbody>
          </table>
          <h3>Threshold Rules</h3>
          <p>Each rule specifies a <code>threshold</code> (minimum required signers) and a <code>signers</code> set. Signers can reference the bot's own keys or keys from controller bots.</p>
          {policy_code}
        </section>

        <section id="controllers" class="doc-section">
          <h2>Controller Delegation</h2>
          <p>A controller is a bot-to-bot trust relationship. A controller bot can be granted specific permissions over another bot, enabling hierarchical management.</p>
          <h3>Delegation Model</h3>
          <ul>
            <li>A bot lists controller bots in its <code>controllers</code> array</li>
            <li>Each controller entry specifies the controller bot ID and allowed permissions</li>
            <li>Controller keys can be used in <code>proof_set</code> entries with a <code>controller_bot_id</code> reference</li>
            <li>The registry resolves controller keys during signature verification</li>
          </ul>
          <p>Controller bots must be registered in the registry and have <code>active</code> status. Revoked controllers cannot sign on behalf of other bots.</p>
        </section>

        <section id="attestations" class="doc-section">
          <h2>Attestations</h2>
          <p>An attestation is a signed statement one bot makes about another. Attestations are first-class objects stored on the subject bot's record.</p>
          <h3>Attestation Fields</h3>
          <table>
            <thead><tr><th>Field</th><th>Description</th></tr></thead>
            <tbody>
              <tr><td><code>issuer_bot_id</code></td><td>Bot ID of the attestation issuer</td></tr>
              <tr><td><code>type</code></td><td>Attestation type (e.g. <code>capability</code>, <code>compliance</code>)</td></tr>
              <tr><td><code>statement</code></td><td>Structured claims (JSON object)</td></tr>
              <tr><td><code>signature</code></td><td>Issuer's Ed25519 JWS over canonical attestation payload</td></tr>
              <tr><td><code>issued_at</code></td><td>Issuance timestamp</td></tr>
              <tr><td><code>expires_at</code></td><td>Optional expiration timestamp</td></tr>
            </tbody>
          </table>
          <p>The registry verifies that the issuer bot exists, has active status, and that the referenced key is valid before accepting the attestation.</p>
        </section>

        <section id="auth-flow" class="doc-section">
          <h2>Auth Flow</h2>
          <p>The complete authentication flow for mutation operations:</p>
          {auth_flow_code}
          <p>For multi-signature operations, include a <code>proof_set</code> array. Each entry references a <code>key_ref</code> with <code>key_id</code> and optional <code>controller_bot_id</code>.</p>
        </section>
        "##,
        bot_id_code = code_block("urn:bot:sha256:{hex(SHA-256(pk))}"),
        single_proof_code = code_block(
            r#"{
  "proof": {
    "algorithm": "Ed25519",
    "key_id": "k1",
    "created": "2026-02-15T00:00:00Z",
    "jws": "<detached-jws>"
  }
}"#
        ),
        multi_proof_code = code_block(
            r#"{
  "proof_set": [
    {
      "algorithm": "Ed25519",
      "key_ref": { "key_id": "k1" },
      "created": "2026-02-15T00:00:00Z",
      "jws": "<detached-jws-1>"
    },
    {
      "algorithm": "Ed25519",
      "key_ref": { "key_id": "k2", "controller_bot_id": "urn:bot:sha256:..." },
      "created": "2026-02-15T00:00:00Z",
      "jws": "<detached-jws-2>"
    }
  ]
}"#
        ),
        policy_code = code_block(
            r#"{
  "policy": {
    "rules": [
      {
        "operation": "revoke_bot",
        "threshold": 2,
        "signers": {
          "keys": ["k1", "k2"],
          "controllers": ["urn:bot:sha256:..."]
        }
      }
    ]
  }
}"#
        ),
        auth_flow_code = code_block(
            r#"Client                                  Registry
  |                                        |
  |  1. GET /v1/nonce                      |
  |--------------------------------------->|
  |<--- { nonce: "abc123" }                |
  |                                        |
  |  2. Build payload (JSON)               |
  |  3. JCS-canonicalize payload           |
  |  4. Sign canonical bytes (Ed25519)     |
  |  5. Attach JWS as `proof` field        |
  |                                        |
  |  POST /v1/bots  { ...payload, proof }  |
  |--------------------------------------->|
  |     6. Strip proof, re-canonicalize    |
  |     7. Verify JWS against bot's keys   |
  |     8. Check nonce (anti-replay)       |
  |     9. Evaluate policy thresholds      |
  |<--- 201 Created                        |"#
        ),
    );

    let toc_html = r##"
        <a href="#bot-id">Bot ID</a>
        <a href="#bot-record">Bot Record</a>
        <a href="#proof-model">Proof Model</a>
        <a href="#policy-engine">Policy Engine</a>
        <a href="#controllers">Controllers</a>
        <a href="#attestations">Attestations</a>
        <a href="#auth-flow">Auth Flow</a>
    "##;

    docs_shell(DocsShellArgs {
        page_title: "Protocol Specification",
        page_subtitle: "Bot ID derivation, proof model, policy engine, and trust delegation.",
        breadcrumb: "Protocol",
        sidebar_html: &sidebar_html,
        content_html: &content_html,
        toc_html,
        active_tab: "Protocol",
    })
}

// ---------------------------------------------------------------------------
// API Reference
// ---------------------------------------------------------------------------

pub async fn docs_api() -> impl IntoResponse {
    let api_docs = build_api_docs_model();

    let mut endpoint_nav = String::new();
    for ep in &api_docs.endpoints {
        endpoint_nav.push_str(&format!(
            r##"<a href="#{}" class="side-link"><code>{}</code> <code>{}</code></a>"##,
            endpoint_anchor(&ep.method, &ep.path),
            escape_html(&ep.method),
            escape_html(&ep.path),
        ));
    }

    let sidebar_html = [
        sidebar_section(
            "Getting Started",
            &[
                ("/docs", "Overview", false),
                ("/docs/protocol", "Protocol", false),
                ("/docs/api", "API Reference", true),
                ("/docs/cli", "CLI Reference", false),
            ],
            true,
        ),
        sidebar_section(
            "API Guide",
            &[
                ("#overview", "Overview", false),
                ("#auth-flow", "Auth Flow", false),
                ("#quickstart-reads", "Read Quickstart", false),
                ("#quickstart-mutations", "Mutation Quickstart", false),
                ("#matrix", "Endpoint Matrix", false),
                ("#details", "Endpoint Details", false),
                ("#schemas", "Schema Catalog", false),
            ],
            true,
        ),
        sidebar_section(
            "Tools",
            &[
                ("/swagger", "Swagger UI", false),
                ("/openapi.json", "OpenAPI JSON", false),
            ],
            true,
        ),
    ]
    .join("\n");

    let mut matrix_rows = String::new();
    let mut detail_sections = String::new();
    for ep in &api_docs.endpoints {
        let method_class = match ep.method.as_str() {
            "GET" => "method-get",
            "POST" => "method-post",
            "PATCH" => "method-patch",
            "DELETE" => "method-delete",
            _ => "",
        };
        matrix_rows.push_str(&format!(
            r#"<tr><td><code class="{}">{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>"#,
            method_class,
            escape_html(&ep.method),
            escape_html(&ep.path),
            escape_html(&ep.summary),
            escape_html(&ep.auth)
        ));

        let mut parameter_rows = String::new();
        for p in &ep.parameters {
            let req = if p.required { "yes" } else { "no" };
            parameter_rows.push_str(&format!(
                r#"<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>"#,
                escape_html(&p.name),
                escape_html(&p.location),
                req,
                escape_html(&p.schema),
                escape_html(p.description.as_deref().unwrap_or("-"))
            ));
        }
        if parameter_rows.is_empty() {
            parameter_rows.push_str(
                r#"<tr><td colspan="5" style="color:var(--mono)">No parameters.</td></tr>"#,
            );
        }

        let mut response_rows = String::new();
        for r in &ep.responses {
            response_rows.push_str(&format!(
                r#"<tr><td><code>{}</code></td><td>{}</td></tr>"#,
                escape_html(&r.status),
                escape_html(r.description.as_deref().unwrap_or("-"))
            ));
        }

        let method_class = match ep.method.as_str() {
            "GET" => "method-get",
            "POST" => "method-post",
            "PATCH" => "method-patch",
            "DELETE" => "method-delete",
            _ => "",
        };

        detail_sections.push_str(&format!(
            r##"
            <section id="{anchor}" class="doc-section">
              <h2><code class="{method_class}">{method}</code> <code>{path}</code></h2>
              <p>{summary}</p>
              <p><strong>Auth:</strong> {auth}</p>
              <p><strong>Operation ID:</strong> <code>{op_id}</code></p>
              <p><strong>Request Body:</strong> {body}</p>
              <h3>Parameters</h3>
              <table>
                <thead><tr><th>Parameter</th><th>In</th><th>Required</th><th>Type</th><th>Description</th></tr></thead>
                <tbody>{params}</tbody>
              </table>
              <h3>Responses</h3>
              <table>
                <thead><tr><th>Status</th><th>Description</th></tr></thead>
                <tbody>{responses}</tbody>
              </table>
              {desc}
            </section>
            "##,
            anchor = endpoint_anchor(&ep.method, &ep.path),
            method_class = method_class,
            method = escape_html(&ep.method),
            path = escape_html(&ep.path),
            summary = escape_html(&ep.summary),
            auth = escape_html(&ep.auth),
            op_id = escape_html(ep.operation_id.as_deref().unwrap_or("unknown")),
            body = ep
                .request_body
                .as_ref()
                .map(|rb| format!("<code>{}</code>", escape_html(rb)))
                .unwrap_or_else(|| "none".to_string()),
            params = parameter_rows,
            responses = response_rows,
            desc = ep
                .description
                .as_ref()
                .map(|d| format!("<p>{}</p>", escape_html(d)))
                .unwrap_or_default(),
        ));
    }

    let mut schema_rows = String::new();
    for s in &api_docs.schemas {
        schema_rows.push_str(&format!(
            r#"<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>"#,
            escape_html(&s.name),
            escape_html(&s.kind),
            s.property_count,
            s.required_fields
        ));
    }

    let content_html = format!(
        r##"
        <section id="overview" class="doc-section">
          <h1>API Reference</h1>
          <p>Endpoint contracts and schemas are extracted from the server's OpenAPI model, so docs stay aligned with Rust handlers and types.</p>
          <p>Base URL: <code>https://botnet.pub/v1</code></p>
        </section>
        <section id="auth-flow" class="doc-section">
          <h2>Auth Flow (Mutations)</h2>
          <p>Reads are public. Mutations are proof-authenticated. For mutation routes, include exactly one of <code>proof</code> or <code>proof_set</code> in the JSON body.</p>
          <p>Server verification steps:</p>
          <ol>
            <li>Remove <code>proof</code>/<code>proof_set</code> from payload</li>
            <li>Canonicalize payload with JCS</li>
            <li>Verify Ed25519 detached JWS signatures</li>
            <li>Resolve signer keys (self + controller keys when present)</li>
            <li>Enforce policy threshold for the operation</li>
          </ol>
          {auth_code}
        </section>
        <section id="quickstart-reads" class="doc-section">
          <h2>Read Quickstart</h2>
          {read_code}
        </section>
        <section id="quickstart-mutations" class="doc-section">
          <h2>Mutation Quickstart</h2>
          <p>1) Build the operation payload file without proof fields.</p>
          <p>2) Canonicalize and sign that payload using your Ed25519 key.</p>
          <p>3) Attach <code>proof</code> (or <code>proof_set</code>) and submit.</p>
          {mutation_code}
        </section>
        <section id="matrix" class="doc-section">
          <h2>Endpoint Matrix</h2>
          <table>
            <thead><tr><th>Method</th><th>Path</th><th>Summary</th><th>Auth</th></tr></thead>
            <tbody>{matrix}</tbody>
          </table>
        </section>
        <section id="details" class="doc-section">
          <h2>Endpoint Details</h2>
          <p>Each endpoint below includes operation ID, auth semantics, parameters, request body shape, and response codes.</p>
        </section>
        {details}
        <section id="schemas" class="doc-section">
          <h2>Schema Catalog</h2>
          <table>
            <thead><tr><th>Schema</th><th>Kind</th><th>Properties</th><th>Required</th></tr></thead>
            <tbody>{schemas}</tbody>
          </table>
        </section>
        "##,
        auth_code = code_block(
            r#"{
  "proof": {
    "algorithm": "Ed25519",
    "key_id": "k1",
    "created": "2026-02-15T00:00:00Z",
    "jws": "<detached-jws>"
  }
}"#
        ),
        read_code = code_block(
            r#"# service metadata
curl -sSf https://botnet.pub/v1

# health
curl -sSf https://botnet.pub/health

# stats
curl -sSf https://botnet.pub/v1/stats

# search
curl -sSf "https://botnet.pub/v1/search?q=assistant&limit=5"

# fetch by id
curl -sSf https://botnet.pub/v1/bots/<BOT_ID>"#
        ),
        mutation_code = code_block(
            r#"# create bot (signed payload)
curl -sSf -X POST https://botnet.pub/v1/bots \
  -H "content-type: application/json" \
  --data @signed-bot-record.json

# add key (signed payload)
curl -sSf -X POST https://botnet.pub/v1/bots/<BOT_ID>/keys \
  -H "content-type: application/json" \
  --data @signed-add-key.json

# revoke bot (signed payload)
curl -sSf -X POST https://botnet.pub/v1/bots/<BOT_ID>/revoke \
  -H "content-type: application/json" \
  --data @signed-revoke.json"#
        ),
        matrix = matrix_rows,
        details = detail_sections,
        schemas = schema_rows,
    );

    let toc_html = r##"
        <a href="#overview">Overview</a>
        <a href="#auth-flow">Auth Flow</a>
        <a href="#quickstart-reads">Read Quickstart</a>
        <a href="#quickstart-mutations">Mutation Quickstart</a>
        <a href="#matrix">Endpoint Matrix</a>
        <a href="#details">Endpoint Details</a>
        <a href="#schemas">Schema Catalog</a>
    "##;

    docs_shell(DocsShellArgs {
        page_title: "API Reference",
        page_subtitle: "Human guide plus generated OpenAPI route and schema reference.",
        breadcrumb: "API Reference",
        sidebar_html: &sidebar_html,
        content_html: &content_html,
        toc_html,
        active_tab: "API",
    })
}

// ---------------------------------------------------------------------------
// CLI Reference
// ---------------------------------------------------------------------------

pub async fn docs_cli() -> impl IntoResponse {
    let cli_docs = generate_cli_docs();
    let mut command_docs = Vec::new();
    flatten_cli_commands(&cli_docs.commands, &mut command_docs);

    let mut command_nav = String::new();
    for c in &cli_docs.commands {
        command_nav.push_str(&format!(
            r##"<a href="#{}" class="side-link"><code>{}</code></a>"##,
            cli_command_anchor(c),
            escape_html(&c.invocation)
        ));
    }

    let commands_section = format!(
        r#"<details open><summary>Top Commands</summary>{}</details>"#,
        command_nav
    );
    let sidebar_html = [
        sidebar_section(
            "Getting Started",
            &[
                ("/docs", "Overview", false),
                ("/docs/protocol", "Protocol", false),
                ("/docs/api", "API Reference", false),
                ("/docs/cli", "CLI Reference", true),
            ],
            true,
        ),
        sidebar_section(
            "CLI Guide",
            &[
                ("#install", "Install", false),
                ("#quickstart", "Quickstart", false),
                ("#signing", "Signing Model", false),
                ("#inputs", "JSON Inputs", false),
                ("#playbooks", "Playbooks", false),
                ("#catalog", "Catalog", false),
                ("#details", "Command Details", false),
            ],
            true,
        ),
        commands_section,
    ]
    .join("\n");

    let mut catalog_rows = String::new();
    let mut detail_sections = String::new();
    for c in &command_docs {
        let guide = cli_command_explainer(c);
        catalog_rows.push_str(&format!(
            r#"<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>"#,
            escape_html(&c.invocation),
            escape_html(guide.purpose),
            escape_html(c.about.as_deref().unwrap_or("-")),
            escape_html(&c.usage)
        ));

        detail_sections.push_str(&format!(
            r##"
            <section id="{anchor}" class="doc-section">
              <h2><code>{invocation}</code></h2>
              <p>{about}</p>
              <p><strong>When to use:</strong> {purpose}</p>
              <p><strong>Input file:</strong> {input}</p>
              <p><strong>Usage:</strong> <code>{usage}</code></p>
              <h3>Example</h3>
              {example_code}
              <h3>Help Output</h3>
              {help_code}
            </section>
            "##,
            anchor = cli_command_anchor(c),
            invocation = escape_html(&c.invocation),
            about = escape_html(c.about.as_deref().unwrap_or("No summary available.")),
            purpose = escape_html(guide.purpose),
            input = escape_html(guide.input_file),
            usage = escape_html(&c.usage),
            example_code = code_block(guide.example),
            help_code = code_block(&c.help),
        ));
    }

    let content_html = format!(
        r##"
        <section id="install" class="doc-section">
          <h1>CLI Reference</h1>
          <p>Human task guides combined with generated command metadata from Clap. Practical workflows plus up-to-date usage output from code.</p>
          {install_code}
        </section>
        <section id="quickstart" class="doc-section">
          <h2>Quickstart</h2>
          <p>Run a read-only check first, then run a signed mutation.</p>
          {quick_code}
        </section>
        <section id="signing" class="doc-section">
          <h2>Signing Model</h2>
          <p>These commands require signing flags: <code>register</code>, <code>update</code>, <code>add-key</code>, <code>remove-key</code>, <code>rotate-key</code>, <code>revoke-bot</code>, <code>publish-attestation</code>.</p>
          <p>Read-only commands do not require keys: <code>get</code>, <code>search</code>, <code>nonce</code>.</p>
          <p>Use the same key ID and seed consistently for workflows that mutate the same bot identity.</p>
        </section>
        <section id="inputs" class="doc-section">
          <h2>JSON Inputs</h2>
          <p>Most mutation commands read JSON files. Start with these templates.</p>
          <h3>register / update file (BotRecord)</h3>
          {register_code}
          <h3>add-key file (PublicKey)</h3>
          {addkey_code}
          <h3>rotate-key file</h3>
          {rotate_code}
          <h3>publish-attestation file (Attestation)</h3>
          {attest_code}
        </section>
        <section id="playbooks" class="doc-section">
          <h2>Command Playbooks</h2>
          <p>Common paths depending on your goal.</p>
          <table>
            <thead><tr><th>Goal</th><th>Command Sequence</th></tr></thead>
            <tbody>
              <tr><td>Create and verify a bot</td><td><code>register</code> &rarr; <code>get</code> &rarr; <code>search</code></td></tr>
              <tr><td>Key lifecycle</td><td><code>add-key</code> &rarr; <code>rotate-key</code> &rarr; <code>remove-key</code></td></tr>
              <tr><td>Shutdown identity</td><td><code>revoke-bot</code> (and verify via <code>get</code>)</td></tr>
              <tr><td>Trust signals</td><td><code>publish-attestation</code> to subject bot record</td></tr>
            </tbody>
          </table>
        </section>
        <section id="catalog" class="doc-section">
          <h2>Generated Catalog</h2>
          <table>
            <thead><tr><th>Command</th><th>Purpose</th><th>Help Summary</th><th>Usage</th></tr></thead>
            <tbody>{catalog}</tbody>
          </table>
        </section>
        <section id="details" class="doc-section">
          <h2>Command Details</h2>
          <p>Human notes plus full generated help output for each command.</p>
        </section>
        {details}
        "##,
        install_code = code_block("curl -fsSL https://botnet.pub/install.sh | sh\nbotnet --help"),
        quick_code = code_block(
            "# read-only search\nbotnet --base-url https://botnet.pub/v1 search --q assistant --limit 5\n\n\
             # signed register\nbotnet --base-url https://botnet.pub/v1 \\\n\
             \x20 --key-id k1 \\\n\
             \x20 --secret-seed-hex 0000000000000000000000000000000000000000000000000000000000000000 \\\n\
             \x20 register bot.json"
        ),
        register_code = code_block(r#"{
  "status": "active",
  "display_name": "Example Bot",
  "description": "Automates routine tasks.",
  "public_keys": [
    {
      "key_id": "k1",
      "algorithm": "Ed25519",
      "public_key_multibase": "z6Mke...",
      "purpose": ["signing"],
      "primary": true
    }
  ],
  "capabilities": ["calendar.read", "email.send"]
}"#),
        addkey_code = code_block(r#"{
  "key_id": "k2",
  "algorithm": "Ed25519",
  "public_key_multibase": "z6Mkh...",
  "purpose": ["signing"],
  "primary": false
}"#),
        rotate_code = code_block(r#"{
  "old_key_id": "k1",
  "new_key": {
    "key_id": "k2",
    "algorithm": "Ed25519",
    "public_key_multibase": "z6Mkh...",
    "purpose": ["signing"],
    "primary": true
  }
}"#),
        attest_code = code_block(r#"{
  "issuer_bot_id": "urn:bot:sha256:...",
  "type": "compliance",
  "statement": { "level": "gold" },
  "signature": {
    "algorithm": "Ed25519",
    "key_id": "issuer-key",
    "jws": "<detached-jws>"
  }
}"#),
        catalog = catalog_rows,
        details = detail_sections,
    );

    let toc_html = r##"
        <a href="#install">Install</a>
        <a href="#quickstart">Quickstart</a>
        <a href="#signing">Signing Model</a>
        <a href="#inputs">JSON Inputs</a>
        <a href="#playbooks">Playbooks</a>
        <a href="#catalog">Catalog</a>
        <a href="#details">Command Details</a>
    "##;

    docs_shell(DocsShellArgs {
        page_title: "CLI Reference",
        page_subtitle: "Human workflows plus generated command metadata from Clap.",
        breadcrumb: "CLI Reference",
        sidebar_html: &sidebar_html,
        content_html: &content_html,
        toc_html,
        active_tab: "CLI",
    })
}

// ---------------------------------------------------------------------------
// Swagger + OpenAPI JSON handlers
// ---------------------------------------------------------------------------

pub async fn swagger() -> impl IntoResponse {
    Html(components::swagger_page().to_string())
}

pub async fn openapi_json() -> impl IntoResponse {
    axum::Json(ApiDoc::openapi())
}

pub async fn install_script() -> impl IntoResponse {
    (
        [("content-type", "text/x-shellscript; charset=utf-8")],
        include_str!("../../../../install.sh"),
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_api_docs_model() -> ApiDocsModel {
    let openapi = serde_json::to_value(ApiDoc::openapi()).unwrap_or(Value::Null);

    let mut endpoints = Vec::new();
    if let Some(paths) = openapi.get("paths").and_then(Value::as_object) {
        for (path, path_item) in paths {
            let Some(path_obj) = path_item.as_object() else {
                continue;
            };
            for method in ["get", "post", "patch", "put", "delete", "options", "head"] {
                let Some(operation) = path_obj.get(method).and_then(Value::as_object) else {
                    continue;
                };

                let summary = operation
                    .get("summary")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        operation
                            .get("operationId")
                            .and_then(Value::as_str)
                            .map(prettify_identifier)
                            .unwrap_or_else(|| "Untitled operation".to_string())
                    });
                let description = operation
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let operation_id = operation
                    .get("operationId")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let auth = auth_requirement(method, path).to_string();

                let mut parameters = Vec::new();
                if let Some(params) = operation.get("parameters").and_then(Value::as_array) {
                    for parameter in params {
                        let Some(param) = parameter.as_object() else {
                            continue;
                        };
                        parameters.push(ApiParameterDoc {
                            name: param
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown")
                                .to_string(),
                            location: param
                                .get("in")
                                .and_then(Value::as_str)
                                .unwrap_or("query")
                                .to_string(),
                            required: param
                                .get("required")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            schema: param
                                .get("schema")
                                .map(describe_schema)
                                .unwrap_or_else(|| "unknown".to_string()),
                            description: param
                                .get("description")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                        });
                    }
                }

                let request_body = operation
                    .get("requestBody")
                    .and_then(|body| body.get("content"))
                    .and_then(Value::as_object)
                    .and_then(|content| {
                        content
                            .get("application/json")
                            .or_else(|| content.values().next())
                            .and_then(|entry| entry.get("schema"))
                    })
                    .map(describe_schema);

                let mut responses = Vec::new();
                if let Some(response_map) = operation.get("responses").and_then(Value::as_object) {
                    for (status, response) in response_map {
                        responses.push(ApiResponseDoc {
                            status: status.to_string(),
                            description: response
                                .get("description")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                        });
                    }
                }
                responses.sort_by(|a, b| a.status.cmp(&b.status));

                endpoints.push(ApiEndpointDoc {
                    method: method.to_ascii_uppercase(),
                    path: path.to_string(),
                    summary,
                    description,
                    operation_id,
                    auth,
                    parameters,
                    request_body,
                    responses,
                });
            }
        }
    }
    endpoints.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| method_rank(&a.method).cmp(&method_rank(&b.method)))
    });

    let mut schemas = Vec::new();
    if let Some(schema_map) = openapi
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(Value::as_object)
    {
        for (name, schema) in schema_map {
            let required_fields = schema
                .get("required")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            let property_count = schema
                .get("properties")
                .and_then(Value::as_object)
                .map_or(0, serde_json::Map::len);
            let kind = describe_schema_kind(schema);
            schemas.push(ApiSchemaDoc {
                name: name.clone(),
                kind,
                required_fields,
                property_count,
            });
        }
    }
    schemas.sort_by(|a, b| a.name.cmp(&b.name));

    ApiDocsModel { endpoints, schemas }
}

fn flatten_cli_commands<'a>(commands: &'a [CliCommandDoc], out: &mut Vec<&'a CliCommandDoc>) {
    for command in commands {
        out.push(command);
        flatten_cli_commands(&command.subcommands, out);
    }
}

fn count_cli_commands(commands: &[CliCommandDoc]) -> usize {
    let mut total = 0;
    for command in commands {
        total += 1 + count_cli_commands(&command.subcommands);
    }
    total
}

fn cli_command_anchor(command: &CliCommandDoc) -> String {
    slugify(&command.invocation)
}

fn cli_command_explainer(command: &CliCommandDoc) -> CliCommandGuide {
    match command.invocation.as_str() {
        "botnet register" => CliCommandGuide {
            purpose: "Create a new bot identity from a BotRecord JSON file.",
            input_file: "BotRecord JSON file required.",
            example: "botnet --base-url https://botnet.pub/v1 --key-id k1 --secret-seed-hex <SEED_HEX> register bot.json",
        },
        "botnet get" => CliCommandGuide {
            purpose: "Fetch one bot record by bot ID.",
            input_file: "No file input.",
            example: "botnet --base-url https://botnet.pub/v1 get urn:bot:sha256:<id>",
        },
        "botnet update" => CliCommandGuide {
            purpose: "Update mutable bot fields using a BotRecord JSON file.",
            input_file: "BotRecord JSON file required.",
            example: "botnet --base-url https://botnet.pub/v1 --key-id k1 --secret-seed-hex <SEED_HEX> update urn:bot:sha256:<id> bot-update.json",
        },
        "botnet add-key" => CliCommandGuide {
            purpose: "Attach a new signing key to an existing bot.",
            input_file: "PublicKey JSON file required.",
            example: "botnet --base-url https://botnet.pub/v1 --key-id k1 --secret-seed-hex <SEED_HEX> add-key urn:bot:sha256:<id> new-key.json",
        },
        "botnet remove-key" => CliCommandGuide {
            purpose: "Revoke an existing key on a bot.",
            input_file: "No file input.",
            example: "botnet --base-url https://botnet.pub/v1 --key-id k1 --secret-seed-hex <SEED_HEX> remove-key urn:bot:sha256:<id> k2 --reason compromised",
        },
        "botnet rotate-key" => CliCommandGuide {
            purpose: "Rotate a key in one operation: revoke old key and add new key.",
            input_file: "Rotate JSON file required (old_key_id + new_key).",
            example: "botnet --base-url https://botnet.pub/v1 --key-id k1 --secret-seed-hex <SEED_HEX> rotate-key urn:bot:sha256:<id> rotate.json",
        },
        "botnet revoke-bot" => CliCommandGuide {
            purpose: "Revoke the entire bot identity (status becomes revoked).",
            input_file: "No file input.",
            example: "botnet --base-url https://botnet.pub/v1 --key-id k1 --secret-seed-hex <SEED_HEX> revoke-bot urn:bot:sha256:<id> --reason retired",
        },
        "botnet publish-attestation" => CliCommandGuide {
            purpose: "Publish an issuer-signed attestation to a subject bot.",
            input_file: "Attestation JSON file required.",
            example: "botnet --base-url https://botnet.pub/v1 --key-id issuer-key --secret-seed-hex <SEED_HEX> publish-attestation urn:bot:sha256:<subject> attestation.json",
        },
        "botnet search" => CliCommandGuide {
            purpose: "Find bots by query, status, capability, and limit filters.",
            input_file: "No file input.",
            example: "botnet --base-url https://botnet.pub/v1 search --q assistant --status active --limit 20",
        },
        "botnet nonce" => CliCommandGuide {
            purpose: "Fetch a server nonce for anti-replay signing flows.",
            input_file: "No file input.",
            example: "botnet --base-url https://botnet.pub/v1 nonce",
        },
        _ => CliCommandGuide {
            purpose: "Run this command for specialized workflow actions.",
            input_file: "See generated help output below.",
            example: "botnet --help",
        },
    }
}
