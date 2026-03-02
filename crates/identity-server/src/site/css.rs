/// Shared font imports used by all pages.
pub const FONT_IMPORTS: &str = r#"<link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">"#;

/// CSS variables (design tokens) shared across homepage and docs.
pub const DESIGN_TOKENS: &str = r#"
      :root {
        --bg: #06080d;
        --bg-soft: #0a0d14;
        --card: #0e131d;
        --card-hover: #111827;
        --line: #1b2231;
        --line-2: #2a3347;
        --text: #e5e7ef;
        --muted: #99a4b7;
        --mono: #7a859c;
        --cyan: #22d3ee;
        --green: #22c55e;
        --red: #fb7185;
        --blue: #60a5fa;
        --purple: #a78bfa;
        --yellow: #fbbf24;
        --orange: #f97316;
      }
"#;

/// CSS reset and base styles.
pub const RESET: &str = r#"
      * { box-sizing: border-box; margin: 0; padding: 0; }
      html { scroll-behavior: smooth; }
      body {
        min-height: 100vh;
        color: var(--text);
        font-family: "Manrope", "Space Grotesk", "Avenir Next", "Segoe UI", sans-serif;
        background: var(--bg);
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
      }
      a { color: inherit; }
      code, pre {
        font-family: "IBM Plex Mono", "SFMono-Regular", "Menlo", "Consolas", monospace;
      }
      img { max-width: 100%; display: block; }
"#;

/// Homepage-specific CSS.
pub const HOMEPAGE_CSS: &str = r#"
      body {
        font-family: "Space Grotesk", "Manrope", "Avenir Next", "Segoe UI", sans-serif;
        background:
          radial-gradient(900px 400px at 8% 0%, rgba(34,211,238,0.07), transparent 58%),
          radial-gradient(700px 320px at 92% 18%, rgba(99,102,241,0.06), transparent 60%),
          linear-gradient(180deg, #05070b 0%, #06080d 100%);
      }

      /* ---- Nav ---- */
      .nav {
        position: sticky; top: 0; z-index: 50;
        display: flex; align-items: center; justify-content: space-between;
        max-width: 1200px; margin: 0 auto;
        padding: 0.85rem 1.2rem;
        background: rgba(6, 8, 13, 0.8);
        backdrop-filter: blur(12px);
        border-bottom: 1px solid var(--line);
      }
      .brand {
        color: #f8fafc;
        font-size: 1.05rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-decoration: none;
      }
      .brand span {
        color: var(--mono);
        font-family: "IBM Plex Mono", monospace;
        font-size: 0.9rem;
        margin-right: 0.4rem;
      }
      .nav-links {
        display: flex; align-items: center; gap: 0.3rem;
      }
      .nav-links a {
        text-decoration: none;
        font-family: "IBM Plex Mono", monospace;
        font-size: 0.78rem;
        color: var(--muted);
        padding: 0.45rem 0.7rem;
        border-radius: 8px;
        transition: color 0.15s, background 0.15s;
      }
      .nav-links a:hover { color: #f8fafc; background: rgba(255,255,255,0.04); }
      .github-btn {
        border: 1px solid var(--line-2);
        border-radius: 8px;
        display: inline-flex; align-items: center; gap: 0.35rem;
      }
      .github-btn svg { width: 16px; height: 16px; fill: currentColor; }

      /* ---- Sections container ---- */
      .page { max-width: 1200px; margin: 0 auto; padding: 0 1.2rem; }

      /* ---- Hero ---- */
      .hero {
        margin-top: 2rem;
        display: grid;
        grid-template-columns: 1.15fr 0.85fr;
        gap: 2rem;
        align-items: center;
        min-height: 420px;
      }
      .hero-text { max-width: 600px; }
      .eyebrow {
        display: inline-flex; align-items: center; gap: 0.5rem;
        padding: 0.38rem 0.85rem;
        border-radius: 999px;
        border: 1px solid rgba(34,211,238,0.2);
        background: rgba(34,211,238,0.06);
        font-size: 0.72rem;
        font-family: "IBM Plex Mono", monospace;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: var(--cyan);
      }
      .eyebrow::before {
        content: "";
        width: 7px; height: 7px;
        border-radius: 50%;
        background: var(--green);
        box-shadow: 0 0 10px rgba(34,197,94,0.6);
      }
      .hero h1 {
        margin-top: 1.1rem;
        font-size: clamp(2.4rem, 5vw, 3.8rem);
        font-weight: 700;
        line-height: 1.06;
        letter-spacing: -0.03em;
        color: #f1f5f9;
      }
      .hero h1 em {
        font-style: normal;
        background: linear-gradient(135deg, var(--cyan), var(--blue));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
      }
      .lede {
        margin-top: 1.1rem;
        color: #b0bcd0;
        font-size: 1.08rem;
        line-height: 1.6;
        max-width: 48ch;
      }
      .hero-actions {
        margin-top: 1.5rem;
        display: flex; gap: 0.65rem; flex-wrap: wrap; align-items: center;
      }
      .btn {
        display: inline-flex; align-items: center; gap: 0.4rem;
        text-decoration: none;
        border-radius: 10px;
        padding: 0.72rem 1.1rem;
        font-size: 0.88rem;
        font-weight: 500;
        transition: all 0.15s;
        border: 1px solid var(--line-2);
        color: #d0d8e8;
      }
      .btn:hover { border-color: #475569; color: #f8fafc; }
      .btn-primary {
        background: linear-gradient(135deg, rgba(34,211,238,0.15), rgba(96,165,250,0.15));
        border-color: rgba(34,211,238,0.3);
        color: #e0f2fe;
      }
      .btn-primary:hover {
        background: linear-gradient(135deg, rgba(34,211,238,0.22), rgba(96,165,250,0.22));
        border-color: rgba(34,211,238,0.5);
      }

      /* ---- Install command ---- */
      .install-cmd {
        margin-top: 1.2rem;
        display: inline-flex; align-items: center; gap: 0.5rem;
        padding: 0.6rem 0.85rem;
        border: 1px solid var(--line);
        border-radius: 10px;
        background: rgba(10,15,24,0.7);
        font-family: "IBM Plex Mono", monospace;
        font-size: 0.82rem;
        color: var(--muted);
        max-width: 100%;
      }
      .install-cmd .prompt { color: var(--green); user-select: none; }
      .install-cmd code { color: #d0d8e8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .copy-btn {
        background: none; border: 1px solid var(--line-2); border-radius: 6px;
        color: var(--muted); cursor: pointer; padding: 0.3rem 0.5rem;
        font-size: 0.7rem; font-family: "IBM Plex Mono", monospace;
        transition: all 0.15s; flex-shrink: 0;
      }
      .copy-btn:hover { border-color: var(--cyan); color: var(--cyan); }

      /* ---- Terminal mockup ---- */
      .terminal {
        border: 1px solid var(--line);
        border-radius: 14px;
        background: #0a0f18;
        overflow: hidden;
        box-shadow: 0 8px 32px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.03);
      }
      .terminal-head {
        display: flex; align-items: center; justify-content: space-between;
        padding: 0.6rem 0.75rem;
        border-bottom: 1px solid var(--line);
        background: rgba(255,255,255,0.02);
      }
      .dots { display: flex; gap: 0.38rem; }
      .dots span { width: 8px; height: 8px; border-radius: 50%; display: block; }
      .dots span:nth-child(1) { background: #fb7185; }
      .dots span:nth-child(2) { background: #f59e0b; }
      .dots span:nth-child(3) { background: #34d399; }
      .terminal-title {
        color: var(--mono);
        font-size: 0.7rem;
        font-family: "IBM Plex Mono", monospace;
        letter-spacing: 0.1em;
      }
      .terminal-body { padding: 0.8rem 0.9rem; }
      .term-row {
        display: grid; grid-template-columns: 1fr auto;
        gap: 0.5rem;
        padding: 0.45rem 0;
        border-bottom: 1px dashed rgba(27,34,49,0.7);
        font-family: "IBM Plex Mono", monospace;
        color: #aab4c9;
        font-size: 0.82rem;
      }
      .term-row:last-child { border-bottom: 0; }
      .term-row strong { color: #dbe4f6; font-weight: 500; }
      .good { color: #33d17a; }
      .warn { color: #f97316; }

      /* ---- Stats bar ---- */
      .stats-bar {
        margin-top: 2.5rem;
        border: 1px solid var(--line);
        border-radius: 14px;
        overflow: hidden;
        display: grid;
        grid-template-columns: repeat(6, minmax(0, 1fr));
      }
      .metric {
        padding: 1rem;
        border-right: 1px solid var(--line);
        background: linear-gradient(180deg, rgba(14,19,29,0.9), rgba(10,15,24,0.9));
        text-align: center;
      }
      .metric:last-child { border-right: 0; }
      .metric .k {
        color: var(--mono);
        font-family: "IBM Plex Mono", monospace;
        text-transform: uppercase;
        font-size: 0.63rem;
        letter-spacing: 0.13em;
      }
      .metric .v {
        margin-top: 0.4rem;
        font-size: clamp(1.2rem, 2vw, 1.65rem);
        font-weight: 700;
        letter-spacing: -0.02em;
      }
      .metric:nth-child(1) .v { color: var(--blue); }
      .metric:nth-child(2) .v { color: var(--green); }
      .metric:nth-child(3) .v { color: var(--red); }
      .metric:nth-child(4) .v { color: var(--cyan); }
      .metric:nth-child(5) .v { color: #fda4af; }
      .metric:nth-child(6) .v { color: var(--purple); }

      /* ---- Section headings ---- */
      .section-label {
        font-family: "IBM Plex Mono", monospace;
        font-size: 0.72rem;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        color: var(--cyan);
      }
      .section-heading {
        margin-top: 0.4rem;
        font-size: clamp(1.5rem, 3vw, 2.2rem);
        font-weight: 700;
        letter-spacing: -0.02em;
        color: #f1f5f9;
      }
      .section-sub {
        margin-top: 0.5rem;
        color: var(--muted);
        font-size: 1rem;
        line-height: 1.6;
        max-width: 60ch;
      }

      /* ---- Card grids ---- */
      .grid-2x2 {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 1rem;
      }
      .grid-3x2 {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1rem;
      }
      .card {
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 1.2rem;
        background: var(--card);
        transition: border-color 0.2s, background 0.2s;
      }
      .card:hover { border-color: var(--line-2); background: var(--card-hover); }
      .card-icon {
        width: 36px; height: 36px;
        border-radius: 10px;
        display: flex; align-items: center; justify-content: center;
        font-size: 1.1rem;
        margin-bottom: 0.75rem;
        border: 1px solid var(--line-2);
        background: rgba(255,255,255,0.03);
      }
      .card h3 {
        font-size: 1rem;
        font-weight: 600;
        color: #f1f5f9;
        margin-bottom: 0.4rem;
      }
      .card p {
        color: var(--muted);
        font-size: 0.88rem;
        line-height: 1.55;
      }
      .card-cyan .card-icon { border-color: rgba(34,211,238,0.3); color: var(--cyan); background: rgba(34,211,238,0.08); }
      .card-green .card-icon { border-color: rgba(34,197,94,0.3); color: var(--green); background: rgba(34,197,94,0.08); }
      .card-blue .card-icon { border-color: rgba(96,165,250,0.3); color: var(--blue); background: rgba(96,165,250,0.08); }
      .card-purple .card-icon { border-color: rgba(167,139,250,0.3); color: var(--purple); background: rgba(167,139,250,0.08); }
      .card-red .card-icon { border-color: rgba(251,113,133,0.3); color: var(--red); background: rgba(251,113,133,0.08); }
      .card-yellow .card-icon { border-color: rgba(251,191,36,0.3); color: var(--yellow); background: rgba(251,191,36,0.08); }

      /* ---- Steps ---- */
      .steps {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 1rem;
        counter-reset: step;
      }
      .step {
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 1.2rem;
        background: var(--card);
        counter-increment: step;
        position: relative;
      }
      .step-num {
        display: flex; align-items: center; justify-content: center;
        width: 28px; height: 28px;
        border-radius: 8px;
        font-size: 0.78rem;
        font-weight: 700;
        font-family: "IBM Plex Mono", monospace;
        margin-bottom: 0.75rem;
        border: 1px solid rgba(34,211,238,0.3);
        background: rgba(34,211,238,0.08);
        color: var(--cyan);
      }
      .step h3 { font-size: 0.95rem; font-weight: 600; color: #f1f5f9; margin-bottom: 0.35rem; }
      .step p { color: var(--muted); font-size: 0.85rem; line-height: 1.5; }
      .step pre {
        margin-top: 0.6rem;
        padding: 0.55rem 0.7rem;
        border-radius: 8px;
        border: 1px solid var(--line);
        background: #090d15;
        color: #c8d5e8;
        font-size: 0.75rem;
        overflow-x: auto;
      }

      /* ---- API table ---- */
      .api-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.85rem;
      }
      .api-table th, .api-table td {
        padding: 0.6rem 0.8rem;
        text-align: left;
        border-bottom: 1px solid var(--line);
      }
      .api-table th {
        font-family: "IBM Plex Mono", monospace;
        font-size: 0.72rem;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--mono);
        background: rgba(14,19,29,0.6);
      }
      .api-table tr:hover td { background: rgba(255,255,255,0.02); }
      .api-table code {
        font-size: 0.82rem;
        padding: 0.15rem 0.4rem;
        border-radius: 4px;
        background: rgba(255,255,255,0.04);
      }
      .method-get { color: var(--green); }
      .method-post { color: var(--blue); }
      .method-patch { color: var(--yellow); }
      .method-delete { color: var(--red); }

      /* ---- Footer ---- */
      .footer {
        margin-top: 4rem;
        border-top: 1px solid var(--line);
        padding: 3rem 0 2rem;
      }
      .footer-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 2rem;
        max-width: 1200px;
        margin: 0 auto;
        padding: 0 1.2rem;
      }
      .footer-col h4 {
        font-family: "IBM Plex Mono", monospace;
        font-size: 0.72rem;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--mono);
        margin-bottom: 0.8rem;
      }
      .footer-col a {
        display: block;
        text-decoration: none;
        color: var(--muted);
        font-size: 0.88rem;
        padding: 0.25rem 0;
        transition: color 0.15s;
      }
      .footer-col a:hover { color: #f8fafc; }
      .footer-bottom {
        max-width: 1200px;
        margin: 2rem auto 0;
        padding: 1.2rem 1.2rem 0;
        border-top: 1px solid var(--line);
        display: flex; justify-content: space-between; align-items: center;
        color: var(--mono);
        font-size: 0.8rem;
      }

      /* ---- Responsive ---- */
      @media (max-width: 1024px) {
        .hero { grid-template-columns: 1fr; }
        .hero .terminal { max-width: 500px; }
        .steps { grid-template-columns: repeat(2, 1fr); }
        .grid-3x2 { grid-template-columns: repeat(2, 1fr); }
      }
      @media (max-width: 768px) {
        .nav-links a:not(.github-btn) { display: none; }
        .stats-bar { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        .grid-2x2 { grid-template-columns: 1fr; }
        .grid-3x2 { grid-template-columns: 1fr; }
        .steps { grid-template-columns: 1fr; }
        .footer-grid { grid-template-columns: 1fr; gap: 1.5rem; }
        .hero h1 { font-size: 2.2rem; }
      }
      @media (max-width: 480px) {
        .stats-bar { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      }
"#;

/// Docs-specific CSS (layout, sidebar, TOC, content typography).
pub const DOCS_CSS: &str = r#"
      body {
        font-family: "Manrope", "Space Grotesk", "Avenir Next", "Segoe UI", sans-serif;
        background:
          radial-gradient(900px 360px at 8% -10%, rgba(56, 189, 248, 0.08), transparent 56%),
          radial-gradient(700px 280px at 100% 8%, rgba(99, 102, 241, 0.06), transparent 60%),
          var(--bg);
      }

      /* ---- Topbar ---- */
      .topbar {
        height: 56px;
        border-bottom: 1px solid var(--line);
        display: flex; align-items: center; justify-content: space-between;
        padding: 0 1rem;
        position: sticky; top: 0;
        background: rgba(6, 8, 13, 0.88);
        backdrop-filter: blur(12px);
        z-index: 50;
      }
      .topbar .brand {
        font-weight: 700;
        letter-spacing: 0.03em;
        font-size: 0.95rem;
        text-decoration: none;
        color: #f1f5f9;
      }
      .topbar .brand span {
        color: var(--mono);
        font-family: "IBM Plex Mono", monospace;
        font-size: 0.85rem;
        margin-right: 0.3rem;
      }
      .tabs { display: flex; gap: 0.3rem; }
      .tabs a {
        color: var(--muted);
        text-decoration: none;
        border: 1px solid transparent;
        border-radius: 8px;
        padding: 0.35rem 0.65rem;
        font-size: 0.8rem;
        font-weight: 500;
        transition: all 0.15s;
      }
      .tabs a:hover { color: #dbeafe; background: rgba(255,255,255,0.04); }
      .tabs a.active {
        color: #dbeafe;
        border-color: #2f4367;
        background: rgba(17,26,43,0.8);
      }

      /* ---- Layout ---- */
      .layout {
        display: grid;
        grid-template-columns: 260px minmax(0, 1fr) 200px;
        min-height: calc(100vh - 56px);
      }

      /* ---- Sidebar ---- */
      .sidebar {
        border-right: 1px solid var(--line);
        padding: 1rem 0.75rem;
        background: rgba(10, 15, 24, 0.6);
        position: sticky;
        top: 56px;
        height: calc(100vh - 56px);
        overflow-y: auto;
      }
      .sidebar details { margin-bottom: 0.2rem; }
      .sidebar summary {
        list-style: none;
        cursor: pointer;
        color: var(--mono);
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.11em;
        font-family: "IBM Plex Mono", monospace;
        padding: 0.5rem 0.4rem;
        border-radius: 6px;
        transition: color 0.15s;
        display: flex; align-items: center; gap: 0.35rem;
      }
      .sidebar summary::-webkit-details-marker { display: none; }
      .sidebar summary::before {
        content: "\25B8";
        font-size: 0.65rem;
        transition: transform 0.15s;
        display: inline-block;
      }
      .sidebar details[open] > summary::before { transform: rotate(90deg); }
      .sidebar summary:hover { color: var(--text); }
      .sidebar .side-link {
        display: block;
        color: #b8c4d8;
        text-decoration: none;
        padding: 0.32rem 0.5rem 0.32rem 1.3rem;
        border-radius: 6px;
        font-size: 0.87rem;
        transition: all 0.12s;
      }
      .sidebar .side-link:hover { background: rgba(255,255,255,0.04); color: #f1f5f9; }
      .sidebar .side-link.active {
        background: rgba(34,211,238,0.08);
        color: var(--cyan);
        border-left: 2px solid var(--cyan);
        padding-left: calc(1.3rem - 2px);
      }

      /* ---- Content ---- */
      .content {
        padding: 1.5rem 2rem 3rem;
        max-width: 100%;
        overflow-x: hidden;
      }

      /* ---- Breadcrumbs ---- */
      .breadcrumbs {
        display: flex; align-items: center; gap: 0.35rem;
        font-size: 0.8rem;
        color: var(--mono);
        margin-bottom: 1rem;
      }
      .breadcrumbs a { color: var(--muted); text-decoration: none; }
      .breadcrumbs a:hover { color: var(--cyan); }
      .breadcrumbs .sep { color: var(--line-2); }

      /* ---- Headline ---- */
      .headline {
        border: 1px solid var(--line);
        border-radius: 14px;
        background: var(--card);
        padding: 1.2rem 1.3rem;
      }
      .headline h1 {
        margin: 0;
        font-size: clamp(1.6rem, 3.4vw, 2.1rem);
        font-weight: 700;
        letter-spacing: -0.02em;
      }
      .headline p {
        margin: 0.4rem 0 0;
        color: var(--muted);
        line-height: 1.55;
      }

      /* ---- Doc sections ---- */
      .doc-section {
        margin-top: 1.2rem;
        border: 1px solid var(--line);
        border-radius: 14px;
        background: var(--card);
        padding: 1.2rem 1.3rem;
      }
      .doc-section h1,
      .doc-section h2 {
        margin: 0 0 0.5rem;
        font-weight: 700;
        letter-spacing: -0.01em;
        line-height: 1.3;
      }
      .doc-section h1 { font-size: 1.55rem; }
      .doc-section h2 { font-size: 1.25rem; }
      .doc-section h3 { font-size: 1.05rem; margin: 0 0 0.4rem; }
      .doc-section p {
        margin: 0 0 0.5rem;
        color: var(--muted);
        line-height: 1.65;
      }
      .doc-section p:last-child { margin-bottom: 0; }
      .doc-section ol, .doc-section ul {
        margin: 0.4rem 0 0.6rem;
        padding-left: 1.3rem;
        color: var(--muted);
        line-height: 1.6;
      }
      .doc-section li + li { margin-top: 0.2rem; }

      /* ---- Code blocks ---- */
      .code-block {
        position: relative;
        margin: 0.75rem 0 0;
      }
      .code-block pre {
        margin: 0;
        border: 1px solid var(--line);
        border-radius: 10px;
        background: #080c14;
        color: #e8eef8;
        padding: 0.85rem 1rem;
        overflow-x: auto;
        font-size: 0.83rem;
        line-height: 1.55;
      }
      .code-block .copy-btn {
        position: absolute;
        top: 0.5rem; right: 0.5rem;
        background: rgba(14,19,29,0.9);
        border: 1px solid var(--line-2);
        border-radius: 6px;
        color: var(--muted);
        cursor: pointer;
        padding: 0.25rem 0.5rem;
        font-size: 0.68rem;
        font-family: "IBM Plex Mono", monospace;
        transition: all 0.15s;
        z-index: 2;
      }
      .code-block .copy-btn:hover { border-color: var(--cyan); color: var(--cyan); }

      /* ---- Inline code ---- */
      .doc-section code {
        font-size: 0.85em;
        padding: 0.15rem 0.4rem;
        border-radius: 5px;
        background: rgba(255,255,255,0.06);
        border: 1px solid rgba(255,255,255,0.06);
      }
      .code-block code {
        padding: 0; background: none; border: none;
      }

      /* ---- Tables ---- */
      table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 0.6rem;
        font-size: 0.88rem;
      }
      th, td {
        border: 1px solid var(--line);
        padding: 0.55rem 0.7rem;
        text-align: left;
        vertical-align: top;
      }
      th {
        background: rgba(14,19,29,0.6);
        font-weight: 600;
        font-size: 0.82rem;
        color: #c0c8d8;
      }
      tbody tr:nth-child(even) td { background: rgba(255,255,255,0.015); }
      tbody tr:hover td { background: rgba(255,255,255,0.03); }

      /* ---- Doc grid (choose path) ---- */
      .doc-grid {
        margin-top: 0.7rem;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 0.75rem;
      }
      .mini-card {
        border: 1px solid var(--line);
        border-radius: 10px;
        padding: 1rem;
        background: rgba(8,12,20,0.6);
        transition: border-color 0.15s;
      }
      .mini-card:hover { border-color: var(--line-2); }
      .mini-card h3 { margin: 0; font-size: 1rem; }
      .mini-card p { margin-top: 0.3rem; font-size: 0.87rem; }
      .mini-card a {
        display: inline-block;
        margin-top: 0.5rem;
        color: var(--cyan);
        text-decoration: none;
        font-size: 0.87rem;
        font-weight: 500;
      }
      .mini-card a:hover { text-decoration: underline; }

      /* ---- TOC ---- */
      .toc {
        border-left: 1px solid var(--line);
        padding: 1rem 0.8rem;
        background: rgba(10, 15, 24, 0.5);
        position: sticky;
        top: 56px;
        height: calc(100vh - 56px);
        overflow-y: auto;
      }
      .toc h3 {
        margin: 0 0 0.5rem;
        color: var(--mono);
        font-size: 0.7rem;
        text-transform: uppercase;
        letter-spacing: 0.11em;
        font-family: "IBM Plex Mono", monospace;
      }
      .toc nav { display: grid; gap: 0.15rem; }
      .toc a {
        color: #a0aabb;
        text-decoration: none;
        font-size: 0.82rem;
        padding: 0.25rem 0.45rem;
        border-radius: 4px;
        border-left: 2px solid transparent;
        transition: all 0.12s;
      }
      .toc a:hover { color: #f1f5f9; }
      .toc a.toc-active {
        color: var(--cyan);
        border-left-color: var(--cyan);
        background: rgba(34,211,238,0.06);
      }

      /* ---- Responsive ---- */
      @media (max-width: 1100px) {
        .layout { grid-template-columns: 240px minmax(0, 1fr); }
        .toc { display: none; }
      }
      @media (max-width: 760px) {
        .layout { grid-template-columns: 1fr; }
        .sidebar {
          position: static;
          height: auto;
          border-right: 0;
          border-bottom: 1px solid var(--line);
        }
        .tabs { display: none; }
        .content { padding: 1rem; }
      }
"#;
