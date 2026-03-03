use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Html,
};
use identity_core::BotRecord;

use crate::AppState;

use super::{components, css, util};

pub async fn bot_profile(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
) -> (StatusCode, Html<String>) {
    match state.store.get_bot(&bot_id).await {
        Ok(Some(bot)) => {
            let html = render_profile(&bot_id, &bot);
            (StatusCode::OK, Html(html))
        }
        _ => {
            let html = render_not_found(&bot_id);
            (StatusCode::NOT_FOUND, Html(html))
        }
    }
}

fn render_profile(bot_id: &str, bot: &BotRecord) -> String {
    let nav = components::nav_bar();
    let footer = components::footer();
    let e_bot_id = util::escape_html(bot_id);

    let display_name = bot.display_name.as_deref().unwrap_or("Unnamed Bot");
    let e_name = util::escape_html(display_name);

    let status_html = status_badge(&bot.status);

    let description_html = bot
        .description
        .as_deref()
        .map(|d| {
            format!(
                r#"<p class="profile-description">{}</p>"#,
                util::escape_html(d)
            )
        })
        .unwrap_or_default();

    let meta_html = render_meta(bot, &e_bot_id);
    let owner_html = render_owner_section(bot);
    let keys_html = render_keys_section(bot);
    let endpoints_html = render_endpoints_section(bot);
    let capabilities_html = render_capabilities_section(bot);
    let controllers_html = render_controllers_section(bot);
    let policy_html = render_policy_section(bot);
    let attestations_html = render_attestations_section(bot);
    let evidence_html = render_evidence_section(bot);
    let raw_json_html = render_raw_json(bot_id, bot);

    format!(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{e_name} &mdash; botnet.pub</title>
    {fonts}
    <style>
{tokens}
{reset}
{profile}
    </style>
  </head>
  <body>
    {nav}

    <div class="page">

      <div class="profile-header">
        <div style="display:flex;align-items:center;gap:0.75rem;flex-wrap:wrap;margin-bottom:0.3rem">
          <h1>{e_name}</h1>
          {status_html}
        </div>
        <div class="bot-id-row">
          <code>{e_bot_id}</code>
          <button class="copy-btn" data-copy="{e_bot_id}">copy</button>
        </div>
        {description_html}
        {meta_html}
      </div>

      {owner_html}
      {keys_html}
      {endpoints_html}
      {capabilities_html}
      {controllers_html}
      {policy_html}
      {attestations_html}
      {evidence_html}
      {raw_json_html}

    </div>

    {footer}
    {copy_js}
  </body>
</html>"##,
        e_name = e_name,
        fonts = css::FONT_IMPORTS,
        tokens = css::DESIGN_TOKENS,
        reset = css::RESET,
        profile = css::PROFILE_CSS,
        nav = nav,
        status_html = status_html,
        e_bot_id = e_bot_id,
        description_html = description_html,
        meta_html = meta_html,
        owner_html = owner_html,
        keys_html = keys_html,
        endpoints_html = endpoints_html,
        capabilities_html = capabilities_html,
        controllers_html = controllers_html,
        policy_html = policy_html,
        attestations_html = attestations_html,
        evidence_html = evidence_html,
        raw_json_html = raw_json_html,
        footer = footer,
        copy_js = components::COPY_JS,
    )
}

fn render_not_found(bot_id: &str) -> String {
    let nav = components::nav_bar();
    let footer = components::footer();
    let e_bot_id = util::escape_html(bot_id);

    format!(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Bot Not Found &mdash; botnet.pub</title>
    {fonts}
    <style>
{tokens}
{reset}
{profile}
    </style>
  </head>
  <body>
    {nav}

    <div class="page">
      <div class="not-found">
        <h1>404</h1>
        <p>No bot found with this identifier.</p>
        <code>{e_bot_id}</code>
      </div>
    </div>

    {footer}
  </body>
</html>"##,
        fonts = css::FONT_IMPORTS,
        tokens = css::DESIGN_TOKENS,
        reset = css::RESET,
        profile = css::PROFILE_CSS,
        nav = nav,
        e_bot_id = e_bot_id,
        footer = footer,
    )
}

fn status_badge(status: &identity_core::BotStatus) -> String {
    let (class, label) = match status {
        identity_core::BotStatus::Active => ("status-active", "active"),
        identity_core::BotStatus::Deprecated => ("status-deprecated", "deprecated"),
        identity_core::BotStatus::Revoked => ("status-revoked", "revoked"),
    };
    format!(r#"<span class="status-badge {class}">{label}</span>"#)
}

fn bot_link(bot_id: &str) -> String {
    let escaped = util::escape_html(bot_id);
    format!(r#"<a class="bot-link" href="/bots/{escaped}">{escaped}</a>"#)
}

fn render_meta(bot: &BotRecord, e_bot_id: &str) -> String {
    let mut items = Vec::new();

    if let Some(v) = bot.version {
        items.push(format!("<span><strong>version</strong> {v}</span>"));
    }
    if let Some(ref ts) = bot.created_at {
        items.push(format!(
            "<span><strong>created</strong> {}</span>",
            util::escape_html(ts)
        ));
    }
    if let Some(ref ts) = bot.updated_at {
        items.push(format!(
            "<span><strong>updated</strong> {}</span>",
            util::escape_html(ts)
        ));
    }
    if let Some(ref parent) = bot.parent_bot_id {
        items.push(format!(
            "<span><strong>parent</strong> {}</span>",
            bot_link(parent)
        ));
    }

    if items.is_empty() {
        // Always show bot_id in meta if nothing else
        format!(r#"<div class="meta-row"><span><strong>id</strong> {e_bot_id}</span></div>"#)
    } else {
        format!(
            r#"<div class="meta-row">{}</div>"#,
            items.join("\n        ")
        )
    }
}

fn render_owner_section(bot: &BotRecord) -> String {
    let owner = match bot.owner {
        Some(ref o) => o,
        None => return String::new(),
    };

    let mut rows = format!("<dt>type</dt><dd>{}</dd>", util::escape_html(&owner.r#type));
    if let Some(ref id) = owner.id {
        rows.push_str(&format!("<dt>id</dt><dd>{}</dd>", util::escape_html(id)));
    }
    if let Some(ref uri) = owner.contact_uri {
        rows.push_str(&format!(
            "<dt>contact</dt><dd>{}</dd>",
            util::escape_html(uri)
        ));
    }

    format!(
        r#"<div class="profile-section">
        <h2>Owner</h2>
        <dl class="owner-grid">{rows}</dl>
      </div>"#
    )
}

fn render_keys_section(bot: &BotRecord) -> String {
    if bot.public_keys.is_empty() {
        return String::new();
    }

    let mut cards = String::new();
    for key in &bot.public_keys {
        let e_kid = util::escape_html(&key.key_id);
        let algo_tag = format!(
            r#"<span class="key-tag key-tag-algo">{}</span>"#,
            util::escape_html(&key.algorithm)
        );

        let primary_tag = if key.primary == Some(true) {
            r#"<span class="key-tag key-tag-primary">primary</span>"#.to_string()
        } else {
            String::new()
        };

        let revoked_tag = if key.revoked_at.is_some() {
            r#"<span class="key-tag key-tag-revoked">revoked</span>"#.to_string()
        } else {
            String::new()
        };

        let purpose_tags: String = key
            .purpose
            .iter()
            .map(|p| {
                format!(
                    r#"<span class="key-tag key-tag-algo">{}</span>"#,
                    util::escape_html(p)
                )
            })
            .collect::<Vec<_>>()
            .join(" ");

        let multibase = format!(
            r#"<div class="key-multibase">{}</div>"#,
            util::escape_html(&key.public_key_multibase)
        );

        let mut meta_items = Vec::new();
        if let Some(ref from) = key.valid_from {
            meta_items.push(format!("from: {}", util::escape_html(from)));
        }
        if let Some(ref to) = key.valid_to {
            meta_items.push(format!("to: {}", util::escape_html(to)));
        }
        if let Some(ref at) = key.revoked_at {
            meta_items.push(format!("revoked: {}", util::escape_html(at)));
        }
        let meta_html = if meta_items.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div class="key-meta">{}</div>"#,
                meta_items
                    .iter()
                    .map(|m| format!("<span>{m}</span>"))
                    .collect::<Vec<_>>()
                    .join("")
            )
        };

        cards.push_str(&format!(
            r#"<div class="key-card">
          <div class="key-card-header">
            <code>{e_kid}</code> {algo_tag} {primary_tag} {revoked_tag} {purpose_tags}
          </div>
          {multibase}
          {meta_html}
        </div>"#
        ));
    }

    format!(
        r#"<div class="profile-section">
        <h2>Public Keys</h2>
        {cards}
      </div>"#
    )
}

fn render_endpoints_section(bot: &BotRecord) -> String {
    let endpoints = match bot.endpoints {
        Some(ref eps) if !eps.is_empty() => eps,
        _ => return String::new(),
    };

    let mut rows = String::new();
    for ep in endpoints {
        let e_type = util::escape_html(&ep.r#type);
        let e_url = util::escape_html(&ep.url);
        let auth = ep
            .auth
            .as_deref()
            .map(util::escape_html)
            .unwrap_or_else(|| "&mdash;".to_string());
        rows.push_str(&format!(
            r#"<tr><td><code>{e_type}</code></td><td><a class="bot-link" href="{e_url}" target="_blank" rel="noreferrer">{e_url}</a></td><td>{auth}</td></tr>"#
        ));
    }

    format!(
        r#"<div class="profile-section">
        <h2>Endpoints</h2>
        <table class="profile-table">
          <thead><tr><th>Type</th><th>URL</th><th>Auth</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>"#
    )
}

fn render_capabilities_section(bot: &BotRecord) -> String {
    let caps = match bot.capabilities {
        Some(ref c) if !c.is_empty() => c,
        _ => return String::new(),
    };

    let tags: String = caps
        .iter()
        .map(|c| format!(r#"<span class="cap-tag">{}</span>"#, util::escape_html(c)))
        .collect::<Vec<_>>()
        .join("\n        ");

    format!(
        r#"<div class="profile-section">
        <h2>Capabilities</h2>
        <div>{tags}</div>
      </div>"#
    )
}

fn render_controllers_section(bot: &BotRecord) -> String {
    let controllers = match bot.controllers {
        Some(ref c) if !c.is_empty() => c,
        _ => return String::new(),
    };

    let mut cards = String::new();
    for ctrl in controllers {
        let link = bot_link(&ctrl.controller_bot_id);
        let role = ctrl
            .role
            .as_deref()
            .map(|r| {
                format!(
                    r#" <span class="key-tag key-tag-algo">{}</span>"#,
                    util::escape_html(r)
                )
            })
            .unwrap_or_default();

        let delegation = ctrl
            .delegation
            .as_ref()
            .map(|d| {
                let allows: String = d
                    .allows
                    .iter()
                    .map(|a| format!(r#"<span class="cap-tag">{}</span>"#, util::escape_html(a)))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!(r#"<div style="margin-top:0.4rem"><span style="color:var(--mono);font-size:0.78rem">allows:</span> {allows}</div>"#)
            })
            .unwrap_or_default();

        cards.push_str(&format!(
            r#"<div class="key-card">
          <div class="key-card-header">{link}{role}</div>
          {delegation}
        </div>"#
        ));
    }

    format!(
        r#"<div class="profile-section">
        <h2>Controllers</h2>
        {cards}
      </div>"#
    )
}

fn render_policy_section(bot: &BotRecord) -> String {
    let policy = match bot.policy {
        Some(ref p) => p,
        None => return String::new(),
    };

    let mut rules_rows = String::new();
    for rule in &policy.rules {
        rules_rows.push_str(&format!(
            r#"<tr><td><code>{}</code></td><td>{}</td><td>{} of set <code>{}</code></td></tr>"#,
            util::escape_html(&rule.operation),
            util::escape_html(&rule.r#type),
            rule.m,
            util::escape_html(&rule.set_id),
        ));
    }

    let mut signer_sets_html = String::new();
    for set in &policy.signer_sets {
        let members: String = set
            .members
            .iter()
            .map(|m| {
                let kid = util::escape_html(&m.r#ref.key_id);
                let ctrl = m
                    .r#ref
                    .controller_bot_id
                    .as_deref()
                    .map(|c| format!(" ({})", bot_link(c)))
                    .unwrap_or_default();
                format!("<li><code>{kid}</code>{ctrl}</li>")
            })
            .collect::<Vec<_>>()
            .join("");
        signer_sets_html.push_str(&format!(
            r#"<div style="margin-top:0.6rem"><strong style="color:var(--muted);font-size:0.85rem">Set: <code>{}</code></strong><ul style="margin:0.3rem 0 0 1.2rem;color:var(--muted);font-size:0.85rem">{members}</ul></div>"#,
            util::escape_html(&set.set_id),
        ));
    }

    format!(
        r#"<div class="profile-section">
        <h2>Policy</h2>
        <table class="profile-table">
          <thead><tr><th>Operation</th><th>Type</th><th>Threshold</th></tr></thead>
          <tbody>{rules_rows}</tbody>
        </table>
        {signer_sets_html}
      </div>"#
    )
}

fn render_attestations_section(bot: &BotRecord) -> String {
    let attestations = match bot.attestations {
        Some(ref a) if !a.is_empty() => a,
        _ => return String::new(),
    };

    let mut cards = String::new();
    for att in attestations {
        let issuer = bot_link(&att.issuer_bot_id);
        let e_type = util::escape_html(&att.r#type);
        let statement =
            util::escape_html(&serde_json::to_string_pretty(&att.statement).unwrap_or_default());

        let mut meta_items = Vec::new();
        if let Some(ref id) = att.attestation_id {
            meta_items.push(format!("id: {}", util::escape_html(id)));
        }
        if let Some(ref at) = att.issued_at {
            meta_items.push(format!("issued: {}", util::escape_html(at)));
        }
        if let Some(ref at) = att.expires_at {
            meta_items.push(format!("expires: {}", util::escape_html(at)));
        }
        let meta_html = if meta_items.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div class="key-meta">{}</div>"#,
                meta_items
                    .iter()
                    .map(|m| format!("<span>{m}</span>"))
                    .collect::<Vec<_>>()
                    .join("")
            )
        };

        cards.push_str(&format!(
            r#"<div class="key-card">
          <div class="key-card-header">
            <span class="key-tag key-tag-algo">{e_type}</span>
          </div>
          <div style="font-size:0.82rem;color:var(--mono);margin:0.3rem 0">issuer: {issuer}</div>
          <pre style="margin:0.4rem 0 0;padding:0.6rem 0.8rem;border-radius:8px;border:1px solid var(--line);background:#080c14;color:#e8eef8;font-size:0.75rem;overflow-x:auto;max-height:200px;overflow-y:auto">{statement}</pre>
          {meta_html}
        </div>"#
        ));
    }

    format!(
        r#"<div class="profile-section">
        <h2>Attestations</h2>
        {cards}
      </div>"#
    )
}

fn render_evidence_section(bot: &BotRecord) -> String {
    let evidence = match bot.evidence {
        Some(ref e) if !e.is_empty() => e,
        _ => return String::new(),
    };

    let mut rows = String::new();
    for ev in evidence {
        let e_type = util::escape_html(&ev.r#type);
        let e_uri = util::escape_html(&ev.uri);
        rows.push_str(&format!(
            r#"<tr><td><code>{e_type}</code></td><td><a class="bot-link" href="{e_uri}" target="_blank" rel="noreferrer">{e_uri}</a></td></tr>"#
        ));
    }

    format!(
        r#"<div class="profile-section">
        <h2>Evidence</h2>
        <table class="profile-table">
          <thead><tr><th>Type</th><th>URI</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>"#
    )
}

fn render_raw_json(bot_id: &str, bot: &BotRecord) -> String {
    let json = serde_json::to_string_pretty(bot).unwrap_or_else(|_| "{}".to_string());
    let e_json = util::escape_html(&json);
    let e_bot_id = util::escape_html(bot_id);
    let api_url = format!("/v1/bots/{e_bot_id}");

    format!(
        r#"<div class="profile-section raw-json">
        <h2>Raw Record</h2>
        <details>
          <summary>Show JSON</summary>
          <pre>{e_json}</pre>
        </details>
        <a class="api-link" href="{api_url}">View API response &rarr;</a>
      </div>"#
    )
}
