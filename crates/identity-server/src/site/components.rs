use crate::GITHUB_REPO;

/// GitHub SVG icon (16x16).
const GITHUB_SVG: &str = r#"<svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>"#;

/// Render the homepage navigation bar.
pub fn nav_bar() -> String {
    format!(
        r#"<nav class="nav">
      <a href="/" class="brand"><span>$</span> botnet.pub</a>
      <div class="nav-links">
        <a href="/docs">Docs</a>
        <a href="/docs/api">API</a>
        <a href="/docs/cli">CLI</a>
        <a href="/swagger">Swagger</a>
        <a class="github-btn" href="https://github.com/{repo}" target="_blank" rel="noreferrer">{svg} GitHub</a>
      </div>
    </nav>"#,
        repo = GITHUB_REPO,
        svg = GITHUB_SVG
    )
}

/// Render terminal window mockup with live-stats rows.
pub fn terminal_window() -> String {
    r#"<div class="terminal">
            <div class="terminal-head">
              <div class="dots"><span></span><span></span><span></span></div>
              <div class="terminal-title">botnet.pub &mdash; live</div>
            </div>
            <div class="terminal-body">
              <div class="term-row"><span><strong>status</strong></span><span id="term_health" class="good">loading</span></div>
              <div class="term-row"><span><strong>bots.active</strong></span><span id="term_active_bots">-</span></div>
              <div class="term-row"><span><strong>bots.revoked</strong></span><span id="term_revoked_bots">-</span></div>
              <div class="term-row"><span><strong>keys.active</strong></span><span id="term_active_keys">-</span></div>
              <div class="term-row"><span><strong>attestations</strong></span><span id="term_attestations">-</span></div>
              <div class="term-row"><span><strong>last.update</strong></span><span id="term_last_update" class="warn">-</span></div>
            </div>
          </div>"#
        .to_string()
}

/// Render the homepage footer.
pub fn footer() -> String {
    format!(
        r#"<footer class="footer">
      <div class="footer-grid">
        <div class="footer-col">
          <h4>Product</h4>
          <a href="/docs">Documentation</a>
          <a href="/docs/api">API Reference</a>
          <a href="/docs/cli">CLI Reference</a>
          <a href="/swagger">Swagger UI</a>
        </div>
        <div class="footer-col">
          <h4>Resources</h4>
          <a href="/docs/protocol">Protocol Spec</a>
          <a href="/openapi.json">OpenAPI Spec</a>
          <a href="/install.sh">Install Script</a>
          <a href="/health">Health Check</a>
        </div>
        <div class="footer-col">
          <h4>Project</h4>
          <a href="https://github.com/{repo}" target="_blank" rel="noreferrer">GitHub</a>
          <a href="https://github.com/{repo}/issues" target="_blank" rel="noreferrer">Issues</a>
          <a href="https://github.com/{repo}/blob/main/LICENSE" target="_blank" rel="noreferrer">MIT License</a>
        </div>
      </div>
      <div class="footer-bottom">
        <span>botnet.pub &mdash; verifiable identities for AI agents</span>
        <span>Open Protocol</span>
      </div>
    </footer>"#,
        repo = GITHUB_REPO
    )
}

/// Render the swagger page HTML.
pub fn swagger_page() -> &'static str {
    r#"<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>AI Bot Registry Swagger</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui'
      });
    </script>
  </body>
</html>
"#
}

/// JavaScript for copy-to-clipboard on code blocks.
pub const COPY_JS: &str = r#"
    <script>
    document.addEventListener('click', function(e) {
      var btn = e.target.closest('.copy-btn');
      if (!btn) return;
      var block = btn.closest('.code-block');
      var pre = block ? block.querySelector('pre') : null;
      var cmd = btn.closest('.install-cmd');
      var text = '';
      if (pre) { text = pre.textContent; }
      else if (cmd) { text = cmd.querySelector('code').textContent; }
      if (!text) return;
      navigator.clipboard.writeText(text.trim()).then(function() {
        btn.textContent = 'copied!';
        setTimeout(function() { btn.textContent = 'copy'; }, 1500);
      });
    });
    </script>"#;

/// JavaScript for live stats polling (homepage).
pub const STATS_JS: &str = r#"
    <script>
      function set(id, v) { var el = document.getElementById(id); if (el) el.textContent = v; }
      async function refresh() {
        try {
          var [hRes, sRes] = await Promise.all([fetch('/health'), fetch('/v1/stats')]);
          var h = await hRes.json();
          var s = await sRes.json();
          set('total_bots', s.total_bots);
          set('active_bots', s.active_bots);
          set('revoked_bots', s.revoked_bots);
          set('active_keys', s.active_keys);
          set('revoked_keys', s.revoked_keys);
          set('total_attestations', s.total_attestations);
          set('term_active_bots', s.active_bots);
          set('term_revoked_bots', s.revoked_bots);
          set('term_active_keys', s.active_keys);
          set('term_attestations', s.total_attestations);
          set('term_last_update', s.last_bot_update || 'none yet');
          var th = document.getElementById('term_health');
          if (h.status === 'ok') {
            if (th) { th.textContent = 'healthy'; th.className = 'good'; }
          } else {
            if (th) { th.textContent = 'degraded'; th.className = 'warn'; }
          }
        } catch (e) {
          var th = document.getElementById('term_health');
          if (th) { th.textContent = 'offline'; th.className = 'warn'; }
        }
      }
      refresh();
      setInterval(refresh, 15000);
    </script>"#;

/// JavaScript for loading bot directory on homepage.
pub const BOTS_JS: &str = r#"
    <script>
    (function() {
      var grid = document.getElementById('bot-directory');
      var label = document.getElementById('bot_count_label');
      if (!grid) return;
      fetch('/v1/search?limit=50')
        .then(function(r) { return r.json(); })
        .then(function(data) {
          var bots = data.results || [];
          if (label && data.count) {
            label.textContent = bots.length + ' of ' + data.count + ' total';
          }
          if (!bots.length) {
            grid.innerHTML = '<p style="color:var(--muted)">No bots registered yet.</p>';
            return;
          }
          grid.innerHTML = bots.map(function(b) {
            var name = b.display_name || 'Unnamed';
            var esc = function(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; };
            var statusClass = b.status === 'active' ? 'good' : (b.status === 'revoked' ? 'bot-revoked' : 'bot-deprecated');
            var desc = b.description ? '<p>' + esc(b.description) + '</p>' : '';
            var keys = b.public_keys ? b.public_keys.length : 0;
            var atts = b.attestations ? b.attestations.length : 0;
            return '<a href="/bots/' + encodeURIComponent(b.bot_id) + '" class="card bot-card">'
              + '<h3>' + esc(name) + ' <span class="' + statusClass + '" style="font-size:0.7rem;font-weight:600;font-family:\'IBM Plex Mono\',monospace">' + esc(b.status) + '</span></h3>'
              + desc
              + '<div class="bot-card-meta">'
              + '<span>' + keys + ' key' + (keys !== 1 ? 's' : '') + '</span>'
              + '<span>' + atts + ' attestation' + (atts !== 1 ? 's' : '') + '</span>'
              + '</div>'
              + '</a>';
          }).join('');
        })
        .catch(function() {
          grid.innerHTML = '<p style="color:var(--muted)">Could not load bots.</p>';
        });
    })();
    </script>"#;

/// JavaScript for TOC active section tracking in docs.
pub const TOC_JS: &str = r#"
    <script>
    (function() {
      var links = document.querySelectorAll('.toc a');
      if (!links.length) return;
      var sections = [];
      links.forEach(function(a) {
        var id = a.getAttribute('href');
        if (id && id.startsWith('#')) {
          var el = document.getElementById(id.substring(1));
          if (el) sections.push({ el: el, link: a });
        }
      });
      if (!sections.length) return;
      var observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
          if (entry.isIntersecting) {
            links.forEach(function(l) { l.classList.remove('toc-active'); });
            var match = sections.find(function(s) { return s.el === entry.target; });
            if (match) match.link.classList.add('toc-active');
          }
        });
      }, { rootMargin: '-80px 0px -60% 0px', threshold: 0 });
      sections.forEach(function(s) { observer.observe(s.el); });
    })();
    </script>"#;
