# -*- coding: utf-8 -*-
import os
import re

with open("frontend/index.html", "r", encoding="utf-8") as f:
    old_html = f.read()

# Extract the existing sections (from Overview to Settings)
sec_start = old_html.find('<!-- SECTION: OVERVIEW -->')
sec_end = old_html.find('<!-- COMMAND PALETTE MODAL -->')
if sec_end == -1:
    sec_end = old_html.find('<script>')
existing_sections_html = old_html[sec_start:sec_end]

# Extract existing JS logic (from inside <script> to </script>)
js_start = old_html.find('<script>') + len('<script>')
js_end = old_html.rfind('</script>')
existing_js = old_html[js_start:js_end]

# Ensure switchPage synchronizes with the active group and subnav pills
switch_page_patch = """
      function switchPage(pageName) {
        activePageName = pageName;
        const targetGroup = findGroupForPage(pageName);
        if (targetGroup !== activeNavGroup) {
          activeNavGroup = targetGroup;
          document.querySelectorAll('.nav-group-item').forEach(el => {
            el.classList.toggle('active', el.dataset.group === targetGroup);
          });
        }
        renderSubnavPills();

        document.querySelectorAll('.page-section').forEach(el => {
          el.style.display = (el.id === `section-${pageName}`) ? 'block' : 'none';
        });

        const grpTitleEl = document.getElementById('page-group-title');
        if (grpTitleEl) grpTitleEl.textContent = navGroups[activeNavGroup]?.title || 'Security Posture';
        
        const crumbEl = document.getElementById('page-crumb-title');
        if (crumbEl) crumbEl.textContent = pageName;
        
        const mainTitleEl = document.getElementById('page-main-title');
        if (mainTitleEl) mainTitleEl.textContent = pageName;
        
        const descEl = document.getElementById('page-main-desc');
        if (descEl) descEl.textContent = pageDescs[pageName] || '';

        // Dynamic page actions
        const actContainer = document.getElementById('page-action-container');
        if (actContainer) {
          actContainer.replaceChildren();
          if (pageName === 'Overview' || pageName === 'Packet Analysis') {
            const btn = document.createElement('button');
            btn.className = 'btn';
            btn.textContent = '📥 Export Summary';
            btn.onclick = () => {
              if (currentScanData && currentScanData.report_ids) {
                window.open(`/api/export/${currentScanData.report_ids.technical}/json`);
              }
            };
            actContainer.appendChild(btn);
          }
        }

        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
"""

# Replace old switchPage in existing JS
if "function switchPage(pageName) {" in existing_js:
    old_switch_start = existing_js.find("function switchPage(pageName) {")
    old_switch_end = existing_js.find("document.querySelectorAll('.nav-item').forEach(btn => {", old_switch_start)
    if old_switch_end != -1:
        existing_js = existing_js[:old_switch_start] + switch_page_patch + existing_js[old_switch_end:]

new_html = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IPsecGuard AI v4.1 — Autonomous Protocol Forensics & Security Assessment Platform</title>
    
    <!-- Google Fonts: Hanken Grotesk & JetBrains Mono -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Hanken+Grotesk:ital,wght@0,300..900;1,300..900&family=JetBrains+Mono:ital,wght@0,100..800;1,100..800&display=swap" rel="stylesheet">
    
    <style>
      :root {
        --bg: #f8f6f8; 
        --surface: #ffffff; 
        --subtle: #f4f1f5; 
        --raised: #eeeaef;
        --text: #1b1b1e; 
        --muted: #716b78; 
        --line: #e3dee7; 
        --line-strong: #d2cbd7;
        --purple: #6b38d4; 
        --purple-soft: #f0eafb; 
        --purple-hover: #5926c2;
        --green: #087a55; 
        --green-soft: #ddf8ed;
        --red: #ba1a1a; 
        --red-soft: #fff0ef; 
        --amber: #a36700;
        --amber-soft: #fff6e6;
        --shadow: 0 2px 8px rgba(35, 20, 45, .045); 
        --shadow-lg: 0 18px 60px rgba(35, 20, 45, .14);
        --observed-bg: #e9ddff;
        --observed-text: #5516be;
        --inferred-bg: #ffddb8;
        --inferred-text: #653e00;
        font-family: "Hanken Grotesk", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        color: var(--text);
        background: var(--bg);
      }
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body { min-height: 100vh; overflow-x: hidden; overscroll-behavior: none; }
      button, input, select, textarea { font: inherit; color: inherit; }
      button:focus-visible, input:focus-visible, select:focus-visible { outline: 3px solid rgba(107,56,212,.22); outline-offset: 2px; }
      code, pre, kbd, .badge, .eyebrow, .nav-group > span, .data-head, .stat small, .mono-tag, .hud-tag { font-family: "JetBrains Mono", monospace; }

      /* Top-level Views */
      .app-view { display: none; }
      .app-view.active { display: block; }
      #workspace-view.active { display: flex; }

      /* Base Layout for Workspace */
      .app-container { display: flex; width: 100%; min-height: 100vh; }
      
      /* Sidebar */
      .sidebar {
        width: 256px;
        position: fixed;
        inset: 0 auto 0 0;
        background: var(--surface);
        border-right: 1px solid var(--line);
        padding: 0 12px 16px;
        display: flex;
        flex-direction: column;
        z-index: 40;
      }
      .brand-box {
        height: 60px;
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 0 4px;
        border-bottom: 1px solid var(--line);
        cursor: pointer;
      }
      .brand-icon {
        width: 32px;
        height: 32px;
        display: grid;
        place-items: center;
        color: var(--purple);
        background: var(--purple-soft);
        border-radius: 9px;
      }
      .brand-title { font-size: 15px; font-weight: 700; letter-spacing: -0.02em; }
      .brand-badge { padding: 2px 6px; background: var(--raised); border-radius: 4px; color: var(--muted); font-size: 10px; font-weight: 600; }
      
      .btn-new-analysis {
        margin: 12px 0 8px;
        width: 100%;
        height: 38px;
        background: var(--surface);
        border: 1px solid var(--line-strong);
        border-radius: 10px;
        font-weight: 600;
        font-size: 13px;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 7px;
        cursor: pointer;
        transition: all 0.16s ease;
        box-shadow: var(--shadow);
      }
      .btn-new-analysis:hover {
        background: var(--subtle);
        border-color: var(--purple);
        color: var(--purple);
        transform: translateY(-1px);
      }
      
      .nav-menu { flex: 1; overflow-y: auto; padding-right: 2px; }
      .nav-group { margin-top: 10px; }
      .nav-group-title {
        display: block;
        font-size: 9.5px;
        letter-spacing: .12em;
        color: var(--muted);
        padding: 0 8px 6px;
        font-weight: 700;
        text-transform: uppercase;
      }

      /* 5 Grouped Main Sidebar Nav Items */
      .nav-group-item {
        width: 100%;
        padding: 10px 12px;
        border: 1px solid transparent;
        border-radius: 10px;
        background: transparent;
        display: flex;
        align-items: center;
        gap: 10px;
        cursor: pointer;
        color: #4b4553;
        font-size: 13px;
        font-weight: 600;
        position: relative;
        transition: all 0.16s ease;
        margin-bottom: 4px;
        text-align: left;
      }
      .nav-group-item:hover { background: var(--subtle); color: var(--text); }
      .nav-group-item.active {
        color: var(--purple);
        background: var(--purple-soft);
        border-color: #e3d5fa;
      }
      .nav-group-item.active::after {
        content: "";
        position: absolute;
        right: 12px;
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: var(--purple);
      }
      .nav-group-item .icon-wrap {
        width: 24px;
        height: 24px;
        display: grid;
        place-items: center;
        border-radius: 6px;
        background: var(--subtle);
        color: var(--muted);
      }
      .nav-group-item.active .icon-wrap {
        background: white;
        color: var(--purple);
      }
      .nav-group-item-subcount {
        margin-left: auto;
        font-size: 10px;
        padding: 2px 6px;
        border-radius: 12px;
        background: var(--raised);
        color: var(--muted);
        font-weight: 700;
      }
      .nav-group-item.active .nav-group-item-subcount {
        background: white;
        color: var(--purple);
      }

      .sidebar-footer {
        margin-top: auto;
        padding-top: 10px;
      }
      .engine-status {
        height: 38px;
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 0 10px;
        border: 1px solid var(--line);
        border-radius: 9px;
        box-shadow: var(--shadow);
        font-size: 12px;
        background: var(--surface);
      }
      .status-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: var(--green);
        display: inline-block;
      }
      .engine-host { margin-left: auto; color: var(--muted); font-size: 10px; }

      /* Main Content Area */
      .workspace {
        margin-left: 256px;
        width: calc(100% - 256px);
        min-width: 0;
        display: flex;
        flex-direction: column;
      }
      .topbar {
        height: 60px;
        border-bottom: 1px solid var(--line);
        background: rgba(255,255,255,.92);
        backdrop-filter: blur(12px);
        display: flex;
        align-items: center;
        gap: 14px;
        padding: 0 24px;
        position: sticky;
        top: 0;
        z-index: 30;
      }
      .global-search {
        width: min(340px, 30vw);
        height: 36px;
        display: flex;
        align-items: center;
        gap: 9px;
        padding: 0 12px;
        color: var(--muted);
        background: var(--subtle);
        border: 1px solid var(--line-strong);
        border-radius: 10px;
        cursor: pointer;
        font-size: 12px;
        text-align: left;
      }
      .global-search span { flex: 1; }
      kbd {
        background: var(--surface);
        border: 1px solid var(--line);
        border-radius: 5px;
        padding: 2px 6px;
        font-size: 10px;
        color: var(--muted);
        box-shadow: 0 1px 0 var(--line);
      }

      .badge {
        min-height: 22px;
        border-radius: 999px;
        padding: 3px 9px;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: var(--subtle);
        color: #59535e;
        font-size: 10px;
        font-weight: 600;
        letter-spacing: .02em;
        white-space: nowrap;
      }
      .badge.purple { background: var(--purple-soft); color: var(--purple); border: 1px solid #e3d5fa; }
      .badge.success { background: var(--green-soft); color: #006b48; border: 1px solid #b8f0d8; }
      .badge.danger { background: #ffe2df; color: var(--red); border: 1px solid #f2cac6; }
      .badge.warning { background: var(--amber-soft); color: var(--amber); border: 1px solid #fed7aa; }

      .top-actions { display: flex; gap: 8px; margin-left: auto; align-items: center; }

      /* Sub-Nav Pill Bar (Grouped Sub-Tabs) */
      .subnav-container {
        background: var(--surface);
        border-bottom: 1px solid var(--line);
        padding: 8px 24px;
        display: flex;
        align-items: center;
        gap: 8px;
        overflow-x: auto;
        position: sticky;
        top: 60px;
        z-index: 25;
      }
      .subnav-pill {
        height: 32px;
        padding: 0 14px;
        border-radius: 20px;
        border: 1px solid var(--line);
        background: var(--subtle);
        color: var(--muted);
        font-size: 12px;
        font-weight: 600;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        cursor: pointer;
        white-space: nowrap;
        transition: all 0.14s ease;
      }
      .subnav-pill:hover {
        background: var(--raised);
        color: var(--text);
        border-color: var(--line-strong);
      }
      .subnav-pill.active {
        background: var(--purple);
        color: white;
        border-color: var(--purple);
        box-shadow: 0 2px 8px rgba(107, 56, 212, 0.25);
      }
      
      /* Buttons */
      .btn {
        min-height: 36px;
        border: 1px solid var(--line-strong);
        background: var(--surface);
        border-radius: 10px;
        padding: 0 14px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 7px;
        cursor: pointer;
        font-weight: 500;
        font-size: 13px;
        transition: .16s ease;
        white-space: nowrap;
        text-decoration: none;
      }
      .btn:hover { transform: translateY(-1px); background: var(--subtle); border-color: #bcb3c4; }
      .btn.primary { background: var(--purple); border-color: var(--purple); color: white; }
      .btn.primary:hover { background: var(--purple-hover); }
      .btn.ghost { border-color: transparent; background: transparent; }
      .btn.danger { color: var(--red); background: var(--red-soft); border-color: #f2cac6; }
      .btn:disabled { opacity: .5; cursor: not-allowed; transform: none; }
      .btn.icon-only { width: 36px; padding: 0; }

      main { padding: 24px clamp(18px, 3vw, 42px) 50px; }
      .page-head {
        max-width: 1440px;
        margin: 0 auto 20px;
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
        gap: 20px;
        flex-wrap: wrap;
      }
      .breadcrumbs {
        display: flex;
        align-items: center;
        gap: 5px;
        font-size: 11px;
        color: var(--muted);
        margin-bottom: 6px;
      }
      .breadcrumbs button { border: 0; background: transparent; padding: 0; color: var(--muted); cursor: pointer; }
      h1 { font-size: clamp(22px, 2.2vw, 30px); letter-spacing: -.03em; line-height: 1.1; margin-bottom: 4px; font-weight: 700; }
      .page-desc { color: var(--muted); font-size: 13px; }

      /* Panels & Cards */
      .panel {
        background: var(--surface);
        border: 1px solid var(--line);
        border-radius: 14px;
        box-shadow: var(--shadow);
        padding: 22px;
        margin-bottom: 16px;
      }
      .section-title {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        margin-bottom: 16px;
      }
      .section-title h2, .section-title h3 { font-size: 17px; font-weight: 600; letter-spacing: -.02em; margin: 0; }
      .eyebrow { color: var(--muted); font-size: 9px; letter-spacing: .12em; text-transform: uppercase; font-weight: 600; }

      /* Metric Grid */
      .metric-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 16px; }
      .stat-card { padding: 18px; background: var(--surface); border: 1px solid var(--line); border-radius: 12px; box-shadow: var(--shadow); }
      .stat-top { display: flex; justify-content: space-between; align-items: center; color: var(--muted); font-size: 12px; }
      .stat-val { font-size: 26px; font-weight: 700; display: block; margin: 12px 0 4px; }
      .stat-note { color: var(--muted); font-size: 11.5px; }

      /* Table Styles */
      table { width: 100%; border-collapse: collapse; }
      th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid var(--line); font-size: 12.5px; }
      th { color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .08em; background: var(--subtle); font-family: "JetBrains Mono", monospace; }
      tr:hover td { background: var(--subtle); }

      /* Code windows & Pre */
      pre, code-box {
        background: #27242a;
        color: #f7f2f8;
        padding: 16px;
        border-radius: 10px;
        font-family: "JetBrains Mono", monospace;
        font-size: 11.5px;
        line-height: 1.6;
        overflow-x: auto;
        display: block;
      }

      /* Command Palette Modal */
      .modal-layer {
        position: fixed;
        inset: 0;
        background: rgba(27,20,32,.4);
        backdrop-filter: blur(4px);
        z-index: 100;
        display: flex;
        justify-content: center;
        align-items: flex-start;
        padding-top: 12vh;
      }
      .command-modal {
        width: min(640px, calc(100vw - 32px));
        max-height: 72vh;
        background: white;
        border: 1px solid var(--line-strong);
        border-radius: 16px;
        box-shadow: var(--shadow-lg);
        overflow: hidden;
      }
      .command-input-box {
        height: 56px;
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 0 18px;
        border-bottom: 1px solid var(--line);
      }
      .command-input-box input { border: 0; outline: 0; flex: 1; font-size: 14px; background: transparent; }
      .command-list { padding: 8px; overflow-y: auto; max-height: 48vh; }
      .command-item {
        width: 100%;
        border: 0;
        background: transparent;
        border-radius: 8px;
        padding: 10px 12px;
        display: flex;
        align-items: center;
        gap: 12px;
        cursor: pointer;
        text-align: left;
        font-size: 13px;
      }
      .command-item:hover, .command-item:focus { background: var(--purple-soft); color: var(--purple); }
      .command-foot {
        height: 40px;
        border-top: 1px solid var(--line);
        background: var(--subtle);
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 0 14px;
        color: var(--muted);
        font-size: 10px;
      }

      /* Form Elements */
      .input-field {
        width: 100%;
        height: 38px;
        background: var(--subtle);
        border: 1px solid var(--line-strong);
        border-radius: 9px;
        padding: 0 12px;
        font-size: 13px;
        outline: none;
      }
      .input-field:focus { border-color: var(--purple); background: white; }

      /* Themes */
      body.theme-dark {
        --bg: #0f0d13;
        --surface: #18151f;
        --subtle: #211c2a;
        --raised: #2a2436;
        --text: #f3eff6;
        --muted: #9c95a6;
        --line: #312b3e;
        --line-strong: #453d56;
        --purple: #9d6fff;
        --purple-soft: #2d1d4f;
        --purple-hover: #8850f7;
        --green: #22c55e;
        --green-soft: #133a24;
        --red: #f87171;
        --red-soft: #451a1a;
        --amber: #fbbf24;
        --amber-soft: #422a0a;
        --shadow: 0 4px 14px rgba(0, 0, 0, .4);
        --shadow-lg: 0 20px 60px rgba(0, 0, 0, .7);
      }
      body.theme-matrix {
        --bg: #040d08;
        --surface: #07170f;
        --subtle: #0c2317;
        --raised: #113020;
        --text: #41fb99;
        --muted: #24975c;
        --line: #14402a;
        --line-strong: #1e5a3c;
        --purple: #00ffaa;
        --purple-soft: #08291a;
        --purple-hover: #33ffbb;
        --green: #00ff88;
        --green-soft: #052615;
        --red: #ff3366;
        --red-soft: #380b16;
        --amber: #ffcc00;
        --amber-soft: #382d00;
      }
      body.theme-contrast {
        --bg: #ffffff;
        --surface: #ffffff;
        --subtle: #f0f0f0;
        --raised: #e0e0e0;
        --text: #000000;
        --muted: #333333;
        --line: #000000;
        --line-strong: #000000;
        --purple: #0000cc;
        --purple-soft: #e0e0ff;
        --green: #008800;
        --red: #cc0000;
        --amber: #bb6600;
      }

      /* Settings Subtabs */
      .settings-subtab {
        height: 36px;
        padding: 0 14px;
        border-radius: 8px;
        font-size: 12.5px;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 6px;
        white-space: nowrap;
      }
      .settings-subtab.active {
        background: var(--purple-soft);
        color: var(--purple);
        border-color: #e3d5fa;
        font-weight: 600;
      }

      /* Cinematic Spotlight & Vignette Tour */
      .tour-vignette-overlay {
        position: fixed;
        inset: 0;
        pointer-events: none;
        z-index: 998;
        background: radial-gradient(circle at var(--spotlight-x, 50%) var(--spotlight-y, 50%), transparent var(--spotlight-radius, 140px), rgba(12, 9, 18, 0.78) calc(var(--spotlight-radius, 140px) + 80px));
        transition: opacity 0.4s ease, background 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        opacity: 0;
      }
      .tour-vignette-overlay.active {
        opacity: 1;
        pointer-events: auto;
      }

      .tour-target-highlight {
        position: relative;
        z-index: 999 !important;
        box-shadow: 0 0 0 4px var(--purple), 0 0 32px rgba(107, 56, 212, 0.6) !important;
        border-radius: 12px;
        transition: box-shadow 0.3s ease;
      }

      /* Floating Tour Narrative Card */
      .tour-narrative-card {
        position: fixed;
        z-index: 1000;
        width: min(440px, calc(100vw - 32px));
        background: var(--surface);
        border: 1px solid var(--purple);
        border-radius: 16px;
        box-shadow: 0 20px 60px rgba(20, 10, 35, 0.35), 0 0 0 1px var(--purple-soft);
        padding: 20px;
        display: none;
        flex-direction: column;
        gap: 12px;
        animation: tourFadeSlideIn 0.35s cubic-bezier(0.16, 1, 0.3, 1);
      }
      @keyframes tourFadeSlideIn {
        from { opacity: 0; transform: translateY(12px) scale(0.97); }
        to { opacity: 1; transform: translateY(0) scale(1); }
      }

      /* Docked Video Player HUD */
      .tour-player-hud {
        position: fixed;
        bottom: 24px;
        left: 50%;
        transform: translateX(-50%);
        z-index: 1001;
        width: min(720px, calc(100vw - 32px));
        background: rgba(22, 17, 28, 0.95);
        backdrop-filter: blur(18px);
        color: white;
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 18px;
        padding: 12px 18px;
        box-shadow: 0 24px 64px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(107, 56, 212, 0.3);
        display: none;
        flex-direction: column;
        gap: 10px;
        animation: tourHudSlideUp 0.4s cubic-bezier(0.16, 1, 0.3, 1);
      }
      @keyframes tourHudSlideUp {
        from { opacity: 0; transform: translate(-50%, 30px); }
        to { opacity: 1; transform: translate(-50%, 0); }
      }

      @keyframes pulseDot {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.4; transform: scale(1.3); }
      }

      /* ============================================================= */
      /* THEMED LANDING PAGE STYLES                                    */
      /* ============================================================= */
      .landing-nav {
        height: 68px;
        border-bottom: 1px solid var(--line);
        background: rgba(255,255,255,.94);
        backdrop-filter: blur(14px);
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0 clamp(20px, 5vw, 60px);
        position: sticky;
        top: 0;
        z-index: 50;
      }
      body.theme-dark .landing-nav, body.theme-matrix .landing-nav {
        background: rgba(24, 21, 31, 0.94);
      }
      .landing-hero {
        padding: clamp(60px, 8vw, 110px) clamp(20px, 5vw, 60px) 70px;
        max-width: 1300px;
        margin: 0 auto;
        display: grid;
        grid-template-columns: 1.15fr 0.85fr;
        gap: 48px;
        align-items: center;
      }
      .hero-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 5px 14px;
        background: var(--purple-soft);
        color: var(--purple);
        border: 1px solid #e3d5fa;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.04em;
        margin-bottom: 18px;
      }
      .hero-title {
        font-size: clamp(34px, 4.2vw, 56px);
        font-weight: 800;
        letter-spacing: -0.035em;
        line-height: 1.08;
        margin-bottom: 18px;
      }
      .hero-title span {
        background: linear-gradient(135deg, var(--purple) 0%, #a855f7 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
      }
      .hero-desc {
        font-size: clamp(15px, 1.3vw, 18px);
        color: var(--muted);
        line-height: 1.6;
        margin-bottom: 28px;
        max-width: 580px;
      }
      .hero-cta-group {
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
        margin-bottom: 36px;
      }
      .hero-terminal-card {
        background: #14111a;
        border: 1px solid #2e263c;
        border-radius: 18px;
        box-shadow: 0 24px 70px rgba(18, 10, 30, 0.45);
        overflow: hidden;
        color: #f3eff6;
      }
      .terminal-head {
        height: 38px;
        background: #1d1827;
        border-bottom: 1px solid #2e263c;
        display: flex;
        align-items: center;
        padding: 0 14px;
        gap: 8px;
      }
      .term-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
      .term-body { padding: 18px; font-family: "JetBrains Mono", monospace; font-size: 12px; line-height: 1.6; }
      
      .landing-section {
        padding: 70px clamp(20px, 5vw, 60px);
        max-width: 1300px;
        margin: 0 auto;
      }
      .landing-grid-5 {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        gap: 18px;
        margin-top: 32px;
      }
      .pillar-card {
        background: var(--surface);
        border: 1px solid var(--line);
        border-radius: 16px;
        padding: 24px;
        box-shadow: var(--shadow);
        transition: transform 0.2s ease, border-color 0.2s ease;
        cursor: pointer;
      }
      .pillar-card:hover {
        transform: translateY(-4px);
        border-color: var(--purple);
      }
      .pillar-icon {
        width: 44px;
        height: 44px;
        border-radius: 12px;
        background: var(--purple-soft);
        color: var(--purple);
        display: grid;
        place-items: center;
        font-size: 20px;
        margin-bottom: 16px;
      }
      .compliance-strip {
        border-top: 1px solid var(--line);
        border-bottom: 1px solid var(--line);
        background: var(--subtle);
        padding: 26px clamp(20px, 5vw, 60px);
        display: flex;
        justify-content: space-around;
        align-items: center;
        flex-wrap: wrap;
        gap: 20px;
      }
      .compliance-item {
        display: flex;
        align-items: center;
        gap: 10px;
        font-weight: 700;
        font-size: 13px;
        color: var(--text);
      }

      /* ============================================================= */
      /* THEMED AUTH LOGIN & SIGN-UP STYLES                            */
      /* ============================================================= */
      .auth-wrapper {
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 30px 20px;
        background: radial-gradient(circle at 50% 30%, rgba(107, 56, 212, 0.08) 0%, transparent 60%), var(--bg);
      }
      .auth-card {
        width: min(480px, 100%);
        background: var(--surface);
        border: 1px solid var(--line-strong);
        border-radius: 20px;
        box-shadow: var(--shadow-lg);
        padding: 36px clamp(20px, 5vw, 36px);
        position: relative;
      }
      .auth-nav-tabs {
        display: flex;
        background: var(--subtle);
        border-radius: 12px;
        padding: 4px;
        margin: 22px 0;
        border: 1px solid var(--line);
      }
      .auth-tab-btn {
        flex: 1;
        height: 38px;
        border: 0;
        background: transparent;
        border-radius: 9px;
        font-weight: 600;
        font-size: 13px;
        cursor: pointer;
        color: var(--muted);
        transition: all 0.15s ease;
      }
      .auth-tab-btn.active {
        background: var(--surface);
        color: var(--purple);
        box-shadow: var(--shadow);
      }
      .auth-form-group {
        margin-bottom: 16px;
      }
      .auth-form-group label {
        display: block;
        font-size: 11.5px;
        font-weight: 700;
        text-transform: uppercase;
        color: var(--muted);
        margin-bottom: 6px;
      }
      .pass-entropy-bar {
        height: 4px;
        border-radius: 2px;
        background: var(--line);
        margin-top: 6px;
        overflow: hidden;
      }
      .pass-entropy-fill {
        height: 100%;
        width: 0%;
        background: var(--green);
        transition: width 0.3s ease, background-color 0.3s ease;
      }

      /* Responsive */
      @media (max-width: 1100px) {
        .sidebar { transform: translateX(-100%); transition: transform 0.2s ease; }
        .sidebar.open { transform: translateX(0); }
        .workspace { margin-left: 0; width: 100%; }
        .metric-grid { grid-template-columns: repeat(2, 1fr); }
        .landing-hero { grid-template-columns: 1fr; }
      }
      @media (max-width: 720px) {
        .metric-grid { grid-template-columns: 1fr; }
        .topbar { padding: 0 12px; }
        .subnav-container { padding: 8px 12px; }
      }
    </style>
  </head>
  <body>

    <!-- ============================================================= -->
    <!-- VIEW 1: DEFENSE-GRADE THEMED LANDING PAGE                     -->
    <!-- ============================================================= -->
    <div id="landing-view" class="app-view active">
      
      <!-- Landing Navigation -->
      <header class="landing-nav">
        <div style="display:flex; align-items:center; gap:10px; cursor:pointer;" onclick="showView('landing')">
          <div class="brand-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/></svg>
          </div>
          <span class="brand-title" style="font-size:17px;">IPsecGuard AI</span>
          <span class="brand-badge">v4.1 DEFENSE</span>
        </div>

        <nav style="display:flex; align-items:center; gap:20px;" class="landing-links">
          <a href="#capabilities" style="text-decoration:none; color:var(--muted); font-size:13px; font-weight:600;">Capabilities</a>
          <a href="#playground" style="text-decoration:none; color:var(--muted); font-size:13px; font-weight:600;">Live Inspector</a>
          <a href="#compliance" style="text-decoration:none; color:var(--muted); font-size:13px; font-weight:600;">NIST Matrix</a>
        </nav>

        <div style="display:flex; align-items:center; gap:10px;">
          <select id="landing-theme-select" class="input-field" style="width:auto; height:34px; padding:0 10px; font-size:12px;" onchange="applyTheme(this.value)">
            <option value="light">☀️ Hanken Light</option>
            <option value="dark">🌙 Midnight SOC</option>
            <option value="matrix">🟢 Cyber Matrix</option>
            <option value="contrast">⚡ High Contrast</option>
          </select>
          <button class="btn ghost" onclick="showView('auth')">
            <span>Operator Sign In</span>
          </button>
          <button class="btn primary" onclick="showView('workspace')">
            <span>🚀 Launch Console</span>
          </button>
        </div>
      </header>

      <!-- Hero Section -->
      <section class="landing-hero">
        <div>
          <div class="hero-badge">
            <span class="status-dot" style="background:var(--purple); width:7px; height:7px; animation:pulseDot 1.5s infinite;"></span>
            <span>NEXT-GEN ZERO-TRUST IPSEC PROTOCOL SUITE</span>
          </div>
          <h1 class="hero-title">
            Autonomous IPsec Forensics & <span>Quantum Posture</span> Engine
          </h1>
          <p class="hero-desc">
            Deep byte-level packet dissection, active MITM downgrade detection, real-time live wire sniffing, and automated NIST SP 800-77 & NSA CNSA 2.0 compliance audit for mission-critical tunnels.
          </p>
          <div class="hero-cta-group">
            <button class="btn primary" style="height:48px; padding:0 24px; font-size:15px; font-weight:700; box-shadow:0 8px 24px rgba(107, 56, 212, 0.25);" onclick="showView('workspace')">
              <span>🚀 Launch Security Console</span>
            </button>
            <button class="btn" style="height:48px; padding:0 20px; font-size:14px; font-weight:600;" onclick="showView('workspace'); setTimeout(startInteractiveTour, 300);">
              <span>🎬 Watch Interactive Demo Tour</span>
            </button>
            <button class="btn ghost" style="height:48px; padding:0 16px; font-size:14px;" onclick="showView('auth')">
              <span>🛡️ Sign In / Register</span>
            </button>
          </div>

          <div style="display:flex; gap:20px; align-items:center; color:var(--muted); font-size:12px;">
            <div>🛡️ <strong>100% Precision & Recall</strong></div>
            <div>⚡ <strong>Zero-Hardware PCAP Engine</strong></div>
            <div>📜 <strong>NIST SP 800-77 Ready</strong></div>
          </div>
        </div>

        <!-- Interactive Hero Terminal HUD -->
        <div class="hero-terminal-card">
          <div class="terminal-head">
            <span class="term-dot" style="background:#ff5f56;"></span>
            <span class="term-dot" style="background:#ffbd2e;"></span>
            <span class="term-dot" style="background:#27c93f;"></span>
            <span style="margin-left:auto; font-size:11px; color:#9c95a6; font-family:'JetBrains Mono';">IPsecGuard AI Telemetry Engine</span>
          </div>
          <div class="term-body">
            <div style="color:#22c55e; margin-bottom:8px;">[SYSTEM READY] Dissector v4.1 initialized</div>
            <div style="color:#9d6fff; margin-bottom:4px;">&gt; INGEST pcap://capture-cnsa2-baseline.pcap</div>
            <div style="color:#f3eff6; margin-bottom:4px;">&gt; IKEv2 SA: SPI_i=0x9f82d1.. SPI_r=0x33ca41..</div>
            <div style="color:#f3eff6; margin-bottom:4px;">&gt; Transform: ENCR_AES_GCM_256 · PRF_HMAC_SHA384</div>
            <div style="color:#f3eff6; margin-bottom:8px;">&gt; Key Exchange: ECP_256 (Group 19) · PFS: ENABLED</div>
            
            <div style="background:#1e182b; border:1px solid #3c2e56; border-radius:8px; padding:10px; margin:10px 0;">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-weight:700; color:#41fb99;">NIST SP 800-77 INDEX: 94/100</span>
                <span class="badge success" style="font-size:9px;">NSA CNSA COMPLIANT</span>
              </div>
              <div style="font-size:11px; color:#9c95a6; margin-top:4px;">HNDL Exposure Risk: 0.00% (Quantum Resilient)</div>
            </div>

            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:12px;">
              <span style="font-size:11px; color:#716b78;">Mode: Tunnel (Encapsulated)</span>
              <button class="btn primary" style="min-height:28px; padding:0 10px; font-size:11px;" onclick="showView('workspace'); switchPage('Overview');">
                <span>View Full Audit ➔</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      <!-- Compliance Standards Ribbon -->
      <div class="compliance-strip" id="compliance">
        <div class="compliance-item">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--green);"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg>
          <span>NIST SP 800-77 Rev. 1</span>
        </div>
        <div class="compliance-item">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--purple);"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg>
          <span>NSA CNSA 2.0 Quantum Matrix</span>
        </div>
        <div class="compliance-item">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--green);"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg>
          <span>RFC 4301 / RFC 7296 (IKEv2)</span>
        </div>
        <div class="compliance-item">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--purple);"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg>
          <span>BSI TR-02102-3 Evaluation</span>
        </div>
        <div class="compliance-item">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--green);"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg>
          <span>FIPS 140-3 Cryptographic Suite</span>
        </div>
      </div>

      <!-- 5 Pillar Capabilities Grid -->
      <section class="landing-section" id="capabilities">
        <div style="text-align:center; max-width:680px; margin:0 auto;">
          <div class="eyebrow" style="color:var(--purple);">Comprehensive Defense Architecture</div>
          <h2 style="font-size:32px; font-weight:800; letter-spacing:-0.03em; margin:8px 0 12px;">
            5 Grouped Defense Modules in One Unified Platform
          </h2>
          <p style="color:var(--muted); font-size:14px; line-height:1.6;">
            Everything required to audit, test, and protect site-to-site tunnels and client VPNs against contemporary and quantum adversaries.
          </p>
        </div>

        <div class="landing-grid-5">
          <!-- Pillar 1 -->
          <div class="pillar-card" onclick="showView('workspace'); switchNavGroup('group-posture'); switchPage('Overview');">
            <div class="pillar-icon">🛡️</div>
            <h3 style="font-size:16px; font-weight:700; margin-bottom:8px;">1. Security Posture & NIST</h3>
            <p style="font-size:12.5px; color:var(--muted); line-height:1.5;">
              5-domain risk score, 3x3 threat matrix, MITRE ATT&CK mappings, and PQC transition exposure.
            </p>
            <div style="margin-top:14px; font-size:11px; font-weight:700; color:var(--purple);">Explore Posture ➔</div>
          </div>

          <!-- Pillar 2 -->
          <div class="pillar-card" onclick="showView('workspace'); switchNavGroup('group-dissector'); switchPage('Packet Analysis');">
            <div class="pillar-icon">🔬</div>
            <h3 style="font-size:16px; font-weight:700; margin-bottom:8px;">2. Deep Forensic Dissector</h3>
            <p style="font-size:12.5px; color:var(--muted); line-height:1.5;">
              Hex dumps, IKE handshake sequence analyzer, Child SA registers, and PCAP diff comparator.
            </p>
            <div style="margin-top:14px; font-size:11px; font-weight:700; color:var(--purple);">Explore Dissector ➔</div>
          </div>

          <!-- Pillar 3 -->
          <div class="pillar-card" onclick="showView('workspace'); switchNavGroup('group-threats'); switchPage('Live Sniffer');">
            <div class="pillar-icon">⚡</div>
            <h3 style="font-size:16px; font-weight:700; margin-bottom:8px;">3. Threat Sniffer & Attacks</h3>
            <p style="font-size:12.5px; color:var(--muted); line-height:1.5;">
              Real-time NIC packet sniffer, virtual packet generator, and active MITM downgrade attack lab.
            </p>
            <div style="margin-top:14px; font-size:11px; font-weight:700; color:var(--purple);">Explore Threat Lab ➔</div>
          </div>

          <!-- Pillar 4 -->
          <div class="pillar-card" onclick="showView('workspace'); switchNavGroup('group-mesh'); switchPage('Benchmark & Accuracy');">
            <div class="pillar-icon">🌐</div>
            <h3 style="font-size:16px; font-weight:700; margin-bottom:8px;">4. Mesh & Benchmarks</h3>
            <p style="font-size:12.5px; color:var(--muted); line-height:1.5;">
              P2P IPsec tunnels (UDP 500/4500), RFC 2544 benchmark engine, precision/recall verification.
            </p>
            <div style="margin-top:14px; font-size:11px; font-weight:700; color:var(--purple);">Explore Benchmarks ➔</div>
          </div>

          <!-- Pillar 5 -->
          <div class="pillar-card" onclick="showView('workspace'); switchNavGroup('group-settings'); switchPage('Settings');">
            <div class="pillar-icon">⚙️</div>
            <h3 style="font-size:16px; font-weight:700; margin-bottom:8px;">5. Settings & Demo Studio</h3>
            <p style="font-size:12.5px; color:var(--muted); line-height:1.5;">
              Interactive video tour with voice narration, operator clearance profile, and 4 theme modes.
            </p>
            <div style="margin-top:14px; font-size:11px; font-weight:700; color:var(--purple);">Explore Studio ➔</div>
          </div>
        </div>
      </section>

      <!-- Interactive Mini Protocol Playground Teaser -->
      <section class="landing-section" id="playground" style="background:var(--subtle); border-radius:24px; margin-bottom:60px;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px; margin-bottom:24px;">
          <div>
            <div class="eyebrow" style="color:var(--purple);">Interactive Protocol Playground</div>
            <h3 style="font-size:22px; font-weight:700; letter-spacing:-0.02em;">Instant Cryptographic Scoring Simulator</h3>
            <p style="color:var(--muted); font-size:13px; margin-top:4px;">Test how cipher selection and key exchange parameters impact NIST SP 800-77 risk ratings.</p>
          </div>
          <button class="btn primary" onclick="showView('workspace'); switchNavGroup('group-threats'); switchPage('Simulation Lab');">
            <span>Open Advanced Simulation Lab ➔</span>
          </button>
        </div>

        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:20px;">
          <div class="panel" style="background:var(--surface);">
            <label style="display:block; font-size:11px; font-weight:700; text-transform:uppercase; color:var(--muted); margin-bottom:6px;">Encryption Cipher</label>
            <select id="landing-sim-cipher" class="input-field" style="margin-bottom:14px;" onchange="updateLandingScoreSimulator()">
              <option value="aes256_gcm">AES-256-GCM (Authenticated AEAD - CNSA 2.0)</option>
              <option value="aes128_gcm">AES-128-GCM (Modern AEAD)</option>
              <option value="aes256_cbc">AES-256-CBC (Legacy Block Cipher)</option>
              <option value="3des_cbc">3DES-CBC (Sweet32 Vulnerable · CVE-2016-2183)</option>
              <option value="des_cbc">DES-56 (Broken · Critical Severity)</option>
            </select>

            <label style="display:block; font-size:11px; font-weight:700; text-transform:uppercase; color:var(--muted); margin-bottom:6px;">Key Exchange (Diffie-Hellman)</label>
            <select id="landing-sim-dh" class="input-field" style="margin-bottom:14px;" onchange="updateLandingScoreSimulator()">
              <option value="curve25519">Curve25519 / Group 20 (High Security ECP)</option>
              <option value="ecp384">ECP-384 / Group 20 (NSA Suite B)</option>
              <option value="modp2048">MODP-2048 / Group 14 (Standard RFC 7296)</option>
              <option value="modp1024">MODP-1024 / Group 2 (Logjam Vulnerable · CVE-2015-4000)</option>
            </select>

            <label style="display:flex; align-items:center; gap:8px; font-size:12px; cursor:pointer;">
              <input type="checkbox" id="landing-sim-pfs" checked onchange="updateLandingScoreSimulator()">
              <span>Enable Perfect Forward Secrecy (PFS / CREATE_CHILD_SA)</span>
            </label>
          </div>

          <div class="panel" style="background:var(--surface); display:flex; flex-direction:column; justify-content:center;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <span class="eyebrow">Calculated Posture Score</span>
              <span class="badge success" id="landing-sim-badge">EXCELLENT</span>
            </div>
            <strong style="font-size:42px; font-weight:800; margin:10px 0 4px; color:var(--purple);" id="landing-sim-score">96 / 100</strong>
            <p style="font-size:12.5px; color:var(--muted);" id="landing-sim-verdict">
              Full NIST SP 800-77 & NSA CNSA 2.0 Compliance. Authenticated AEAD with modern Elliptic Curve Key Exchange.
            </p>
          </div>
        </div>
      </section>

      <!-- Landing Footer -->
      <footer style="border-top:1px solid var(--line); padding:36px clamp(20px, 5vw, 60px); display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px; font-size:12.5px; color:var(--muted);">
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="status-dot"></span>
          <span>IPsecGuard AI v4.1 — Defense-Grade Security Framework</span>
        </div>
        <div style="display:flex; gap:18px;">
          <button class="btn ghost" style="font-size:12px;" onclick="showView('workspace'); switchNavGroup('group-settings'); switchPage('Settings');">Settings</button>
          <button class="btn ghost" style="font-size:12px;" onclick="showView('auth')">Operator Login</button>
          <button class="btn primary" style="font-size:12px;" onclick="showView('workspace')">Console</button>
        </div>
      </footer>

    </div>

    <!-- ============================================================= -->
    <!-- VIEW 2: DEFENSE-GRADE THEMED AUTH (LOGIN / SIGN UP)           -->
    <!-- ============================================================= -->
    <div id="auth-view" class="app-view">
      <div class="auth-wrapper">
        <div class="auth-card">
          
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
            <div style="display:flex; align-items:center; gap:8px; cursor:pointer;" onclick="showView('landing')">
              <div class="brand-icon" style="width:28px; height:28px;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/></svg>
              </div>
              <strong style="font-size:15px;">IPsecGuard Security Access</strong>
            </div>
            <button class="btn ghost" style="font-size:11px; padding:0 8px; min-height:28px;" onclick="showView('landing')">
              ← Back to Home
            </button>
          </div>

          <p style="font-size:12.5px; color:var(--muted);">
            Authenticate to access live wire telemetry, cryptographic keys, and automated remediation playbooks.
          </p>

          <div class="auth-nav-tabs">
            <button class="auth-tab-btn active" id="btn-auth-tab-login" onclick="switchAuthTab('login')">
              🛡️ Operator Sign In
            </button>
            <button class="auth-tab-btn" id="btn-auth-tab-register" onclick="switchAuthTab('register')">
              ⚡ Register Clearance
            </button>
          </div>

          <!-- SIGN IN FORM -->
          <form id="auth-login-form" onsubmit="handleOperatorLogin(event)">
            <div class="auth-form-group">
              <label>Operator ID / Email</label>
              <input type="text" id="auth-login-email" class="input-field" value="operator@ipsecguard.ai" required>
            </div>
            
            <div class="auth-form-group">
              <label>Access Passphrase</label>
              <input type="password" id="auth-login-pass" class="input-field" value="••••••••••••" required>
            </div>

            <div class="auth-form-group">
              <label>Requested Clearance Level</label>
              <select id="auth-login-clearance" class="input-field">
                <option value="Level 5: Top Secret / CNSA 2.0 Clearance">Level 5: Chief SOC Operator / NSA CNSA Clearance</option>
                <option value="Level 3: Security Engineer">Level 3: Security Engineer (Read & Active Attack)</option>
                <option value="Level 1: Analyst">Level 1: Read-Only Protocol Analyst</option>
              </select>
            </div>

            <div style="display:flex; justify-content:space-between; align-items:center; margin:14px 0;">
              <label style="display:flex; align-items:center; gap:8px; font-size:12px; cursor:pointer;">
                <input type="checkbox" id="auth-login-2fa" checked>
                <span>FIDO2 Hardware Key (Simulated)</span>
              </label>
              <span style="font-size:11px; color:var(--purple); cursor:pointer;" onclick="fillDemoOperator()">⚡ 1-Click Demo</span>
            </div>

            <button type="submit" class="btn primary" style="width:100%; height:42px; font-size:14px; font-weight:700; margin-top:4px;">
              <span>🛡️ Authenticate & Launch Console</span>
            </button>

            <button type="button" class="btn" style="width:100%; height:38px; font-size:12.5px; margin-top:8px;" onclick="showView('workspace')">
              <span>Continue as Guest Operator ➔</span>
            </button>
          </form>

          <!-- SIGN UP / REGISTER FORM -->
          <form id="auth-register-form" style="display:none;" onsubmit="handleOperatorRegister(event)">
            <div class="auth-form-group">
              <label>Operator Full Name</label>
              <input type="text" id="auth-reg-name" class="input-field" placeholder="Commander Jane Doe" required>
            </div>

            <div class="auth-form-group">
              <label>Agency / Organization</label>
              <input type="text" id="auth-reg-org" class="input-field" placeholder="US Cyber Command / SOC-Alpha" required>
            </div>

            <div class="auth-form-group">
              <label>Security Clearance Tier</label>
              <select id="auth-reg-clearance" class="input-field">
                <option value="Level 5: Top Secret / CNSA 2.0 Clearance">Tier 5 (Top Secret SCI / CNSA PQC Access)</option>
                <option value="Level 3: Security Engineer">Tier 3 (SecOps Engineer / Packet Dissector)</option>
                <option value="Level 1: Analyst">Tier 1 (SOC Analyst / Read-Only)</option>
              </select>
            </div>

            <div class="auth-form-group">
              <label>Master Security Passphrase</label>
              <input type="password" id="auth-reg-pass" class="input-field" placeholder="Min 12 characters" oninput="calculatePassEntropy(this.value)" required>
              <div class="pass-entropy-bar">
                <div class="pass-entropy-fill" id="pass-entropy-fill"></div>
              </div>
              <small style="color:var(--muted); font-size:10px;" id="pass-entropy-text">NIST SP 800-63B Passphrase Verification</small>
            </div>

            <button type="submit" class="btn primary" style="width:100%; height:42px; font-size:14px; font-weight:700; margin-top:10px;">
              <span>⚡ Register Security Clearance & Launch</span>
            </button>
          </form>

        </div>
      </div>
    </div>

    <!-- ============================================================= -->
    <!-- VIEW 3: MAIN APP WORKSPACE WITH 5 GROUPED SIDEBAR TABS        -->
    <!-- ============================================================= -->
    <div id="workspace-view" class="app-view">
      <div class="app-container">
        
        <!-- SIDEBAR WITH 5 GROUPED TABS -->
        <aside class="sidebar" id="app-sidebar">
          <div class="brand-box" onclick="showView('landing')">
            <div class="brand-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/></svg>
            </div>
            <div>
              <div style="display:flex; align-items:center; gap:6px;">
                <span class="brand-title">IPsecGuard</span>
                <span class="brand-badge">v4.1</span>
              </div>
              <div style="font-size:9.5px; color:var(--muted); font-family:'JetBrains Mono';">AI Security Terminal</div>
            </div>
          </div>

          <button class="btn-new-analysis" id="btn-trigger-upload">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
            <span>New Ingestion / Scan</span>
          </button>

          <!-- 5 GROUPED LEFT SIDEBAR NAVIGATION BUTTONS -->
          <nav class="nav-menu">
            <div class="nav-group">
              <span class="nav-group-title">Defense Modules (5 Groups)</span>

              <!-- GROUP 1: Security Posture -->
              <button class="nav-group-item active" data-group="group-posture" onclick="switchNavGroup('group-posture')">
                <div class="icon-wrap">🛡️</div>
                <div>
                  <div>Security Posture</div>
                  <small style="font-size:10.5px; color:var(--muted); font-weight:normal;">NIST · Risk · Threat Intel</small>
                </div>
                <span class="nav-group-item-subcount">6</span>
              </button>

              <!-- GROUP 2: Deep Dissector -->
              <button class="nav-group-item" data-group="group-dissector" onclick="switchNavGroup('group-dissector')">
                <div class="icon-wrap">🔬</div>
                <div>
                  <div>Traffic Dissector</div>
                  <small style="font-size:10.5px; color:var(--muted); font-weight:normal;">Hex Dumps · SAs · Diff</small>
                </div>
                <span class="nav-group-item-subcount">5</span>
              </button>

              <!-- GROUP 3: Threat Sniffer & Lab -->
              <button class="nav-group-item" data-group="group-threats" onclick="switchNavGroup('group-threats')">
                <div class="icon-wrap">⚡</div>
                <div>
                  <div>Live Sniffer & Lab</div>
                  <small style="font-size:10.5px; color:var(--muted); font-weight:normal;">Wire Sniff · MITM Attacks</small>
                </div>
                <span class="nav-group-item-subcount">2</span>
              </button>

              <!-- GROUP 4: Mesh & Benchmarks -->
              <button class="nav-group-item" data-group="group-mesh" onclick="switchNavGroup('group-mesh')">
                <div class="icon-wrap">🌐</div>
                <div>
                  <div>Mesh & Benchmarks</div>
                  <small style="font-size:10.5px; color:var(--muted); font-weight:normal;">P2P VPN · RFC 2544</small>
                </div>
                <span class="nav-group-item-subcount">4</span>
              </button>

              <!-- GROUP 5: Settings & Studio -->
              <button class="nav-group-item" data-group="group-settings" onclick="switchNavGroup('group-settings')">
                <div class="icon-wrap">⚙️</div>
                <div>
                  <div>Settings & Studio</div>
                  <small style="font-size:10.5px; color:var(--muted); font-weight:normal;">🎬 Demo Tour · Themes</small>
                </div>
                <span class="nav-group-item-subcount">2</span>
              </button>
            </div>
          </nav>

          <!-- SIDEBAR FOOTER -->
          <div class="sidebar-footer">
            <div class="engine-status">
              <span class="status-dot"></span>
              <span>FastAPI Engine</span>
              <span class="engine-host">127.0.0.1:8000</span>
            </div>
          </div>
        </aside>

        <!-- WORKSPACE AREA -->
        <div class="workspace">
          
          <!-- TOPBAR -->
          <header class="topbar">
            <button class="btn ghost icon-only" id="mobile-menu-btn" style="display:none;">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
            </button>

            <button class="global-search" id="btn-open-palette">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>
              <span>Search traffic, SPIs, CVEs, findings...</span>
              <kbd>⌘K</kbd>
            </button>

            <span class="badge success">
              <span class="status-dot"></span>
              Engine Online
            </span>

            <div class="top-actions">
              <!-- Interactive Tour Trigger -->
              <button class="btn" id="btn-topbar-tour" style="background:var(--purple-soft); color:var(--purple); border-color:#e3d5fa; font-weight:600;" onclick="startInteractiveTour()">
                <span class="status-dot" style="background:var(--purple); width:7px; height:7px; animation:pulseDot 1.5s infinite;"></span>
                <span>🎬 Tour</span>
              </button>

              <!-- Theme Quick Select -->
              <select id="topbar-theme-select" class="input-field" style="width:auto; height:36px; padding:0 8px; font-size:12px;" onchange="applyTheme(this.value)">
                <option value="light">☀️ Light</option>
                <option value="dark">🌙 Dark</option>
                <option value="matrix">🟢 Matrix</option>
                <option value="contrast">⚡ Contrast</option>
              </select>

              <!-- Operator Badge / Profile Menu -->
              <div style="display:flex; align-items:center; gap:8px; padding:4px 10px; background:var(--subtle); border:1px solid var(--line); border-radius:10px; cursor:pointer;" onclick="showView('auth')" title="Click to manage clearance">
                <span style="font-size:13px;">🛡️</span>
                <div style="text-align:left; line-height:1.2;">
                  <div style="font-size:11px; font-weight:700;" id="topbar-operator-name">Operator Jane</div>
                  <div style="font-size:9.5px; color:var(--purple); font-weight:600;" id="topbar-operator-tier">Level 5 (CNSA)</div>
                </div>
              </div>

              <!-- Landing Home Button -->
              <button class="btn ghost" onclick="showView('landing')" title="Return to Landing Page">
                <span>🏠 Home</span>
              </button>

              <button class="btn primary" id="btn-upload-top">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/></svg>
                <span>Upload PCAP</span>
              </button>
            </div>
          </header>

          <!-- DYNAMIC SUB-NAV PILL BAR FOR ACTIVE 5-GROUP TAB -->
          <div class="subnav-container" id="workspace-subnav-strip">
            <!-- Dynamically populated based on active group -->
          </div>

          <!-- MAIN PAGE CONTENT -->
          <main>
            
            <!-- Page Header -->
            <div class="page-head">
              <div>
                <div class="breadcrumbs">
                  <button onclick="showView('landing')">Home</button>
                  <span>/</span>
                  <span id="page-group-title" style="color:var(--muted);">Security Posture</span>
                  <span>/</span>
                  <span id="page-crumb-title" style="color:var(--text); font-weight:600;">Overview</span>
                </div>
                <h1 id="page-main-title">Operational Overview</h1>
                <p class="page-desc" id="page-main-desc">Real-time status of the local IPsec security analysis workspace.</p>
              </div>
              
              <div id="page-action-container" style="display:flex; gap:8px;">
                <!-- Dynamic page action buttons -->
              </div>
            </div>

            <!-- HIDDEN FILE INPUT FOR QUICK UPLOAD -->
            <input type="file" id="global-pcap-input" accept=".pcap" style="display:none;">

""" + existing_sections_html + """
          </main>
        </div>

      </div>
    </div>

    <!-- COMMAND PALETTE MODAL -->
    <div class="modal-layer" id="command-palette-modal" style="display:none;">
      <div class="command-modal">
        <div class="command-input-box">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>
          <input type="text" id="palette-search-input" placeholder="Search pages, traffic features, findings, tools...">
          <kbd>ESC</kbd>
        </div>
        <div class="command-list" id="palette-results-box">
          <!-- Command items -->
        </div>
        <div class="command-foot">
          <span><kbd>↑↓</kbd> Navigate</span>
          <span><kbd>↵</kbd> Select</span>
          <span style="margin-left:auto;">IPsecScan Command Palette</span>
        </div>
      </div>
    </div>

    <!-- CINEMATIC VIGNETTE SPOTLIGHT OVERLAY -->
    <div class="tour-vignette-overlay" id="tour-vignette-overlay"></div>

    <!-- FLOATING TOUR NARRATIVE CARD -->
    <div class="tour-narrative-card" id="tour-narrative-card">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <span class="badge purple" id="tour-step-badge">STEP 1 OF 8</span>
        <button class="btn ghost icon-only" style="width:24px; height:24px; padding:0; min-height:0;" onclick="stopInteractiveTour()">✕</button>
      </div>
      <h3 id="tour-step-title" style="font-size:15px; font-weight:700; margin:0;">Operational Overview & NIST SP 800-77 Index</h3>
      <p id="tour-step-desc" style="font-size:12.5px; color:var(--muted); line-height:1.5; margin:0;">
        Real-time calculation of the 5-domain cryptographic risk score and instant compliance posture indicators.
      </p>
      <div id="tour-action-indicator" style="display:none; font-family:'JetBrains Mono'; font-size:11px; color:var(--purple); background:var(--purple-soft); padding:6px 10px; border-radius:6px; border:1px solid #e3d5fa;">
        ⚡ [Simulating PCAP Ingestion & Health Check...]
      </div>
      <div style="display:flex; justify-content:space-between; align-items:center; margin-top:4px;">
        <button class="btn" id="btn-tour-prev" onclick="prevTourStep()">⏮ Previous</button>
        <div style="display:flex; gap:6px;">
          <button class="btn" id="btn-tour-playpause" onclick="toggleTourPlayPause()">⏸ Pause</button>
          <button class="btn primary" id="btn-tour-next" onclick="nextTourStep()">Next ⏭</button>
        </div>
      </div>
    </div>

    <!-- DOCKED VIDEO PLAYER HUD -->
    <div class="tour-player-hud" id="tour-player-hud">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="status-dot" style="background:var(--purple); width:8px; height:8px; animation:pulseDot 1s infinite;"></span>
          <strong style="font-size:13.5px; letter-spacing:-0.01em;">🎬 IPsecGuard AI Interactive Product Tour</strong>
          <span class="badge purple" style="font-size:9.5px;">VIDEO HUD</span>
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
          <button class="btn ghost" id="btn-toggle-voice" style="color:white; font-size:11px; min-height:28px; padding:0 8px;" onclick="toggleTourVoice()">🔊 Voice: ON</button>
          <button class="btn ghost icon-only" style="color:white; width:28px; height:28px; padding:0;" onclick="stopInteractiveTour()">✕</button>
        </div>
      </div>

      <!-- Scrubber Timeline Track -->
      <div id="hud-progress-track" style="height:6px; background:rgba(255,255,255,0.2); border-radius:3px; cursor:pointer; position:relative; overflow:hidden;" onclick="scrubTour(event)">
        <div id="hud-progress-fill" style="height:100%; width:12.5%; background:linear-gradient(90deg, #9d6fff, #41fb99); border-radius:3px; transition:width 0.25s ease;"></div>
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
        <div style="display:flex; align-items:center; gap:10px;">
          <button class="btn primary icon-only" id="hud-playpause-btn" style="width:34px; height:34px; border-radius:50%; padding:0;" onclick="toggleTourPlayPause()">⏸</button>
          <button class="btn ghost icon-only" style="color:white; width:30px; height:30px; padding:0;" onclick="prevTourStep()">⏮</button>
          <button class="btn ghost icon-only" style="color:white; width:30px; height:30px; padding:0;" onclick="nextTourStep()">⏭</button>
          
          <div style="font-size:12px; margin-left:6px;">
            <strong id="hud-step-title" style="display:block; color:white;">1. NIST SP 800-77 Index & Posture Dashboard</strong>
            <small style="color:rgba(255,255,255,0.6);" id="hud-step-counter">Step 1 of 8 · 10s remaining</small>
          </div>
        </div>

        <div style="display:flex; align-items:center; gap:8px;">
          <select id="hud-speed-select" class="input-field" style="height:28px; background:rgba(255,255,255,0.1); color:white; border-color:rgba(255,255,255,0.2); font-size:11px; padding:0 6px;" onchange="setTourSpeed(this.value)">
            <option value="0.75" style="color:black;">0.75x</option>
            <option value="1.0" selected style="color:black;">1.0x (Normal)</option>
            <option value="1.5" style="color:black;">1.5x</option>
            <option value="2.0" style="color:black;">2.0x (Fast)</option>
          </select>
          <button class="btn ghost" style="color:rgba(255,255,255,0.8); font-size:11px; min-height:28px; padding:0 10px;" onclick="stopInteractiveTour()">Exit Tour</button>
        </div>
      </div>
    </div>

    <!-- ============================================================= -->
    <!-- JAVASCRIPT LOGIC & 5-GROUP SUBNAV ROUTING                     -->
    <!-- ============================================================= -->
    <script>
      // 5 Group Definitions mapping grouped sidebar tabs to their sub-pages
      const navGroups = {
        "group-posture": {
          title: "Security Posture",
          icon: "🛡️",
          defaultPage: "Overview",
          pages: ["Overview", "Findings", "Threat Intel", "Quantum", "Compliance", "Remediation"]
        },
        "group-dissector": {
          title: "Traffic Dissector",
          icon: "🔬",
          defaultPage: "Packet Analysis",
          pages: ["Packet Analysis", "IKE Sessions", "Child SAs", "Diff Compare", "Topology"]
        },
        "group-threats": {
          title: "Live Sniffer & Lab",
          icon: "⚡",
          defaultPage: "Live Sniffer",
          pages: ["Live Sniffer", "Simulation Lab"]
        },
        "group-mesh": {
          title: "Mesh & Benchmarks",
          icon: "🌐",
          defaultPage: "Benchmark & Accuracy",
          pages: ["Live P2P VPN", "Benchmark & Accuracy", "Reports", "Scan History"]
        },
        "group-settings": {
          title: "Settings & Studio",
          icon: "⚙️",
          defaultPage: "Settings",
          pages: ["Settings"]
        }
      };

      let activeNavGroup = "group-posture";
      let activePageName = "Overview";

      // Top-level View Router: 'landing' | 'auth' | 'workspace'
      function showView(viewName) {
        document.querySelectorAll('.app-view').forEach(el => el.classList.remove('active'));
        if (viewName === 'landing') {
          document.getElementById('landing-view').classList.add('active');
        } else if (viewName === 'auth') {
          document.getElementById('auth-view').classList.add('active');
        } else {
          document.getElementById('workspace-view').classList.add('active');
          renderSubnavPills();
        }
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }

      // Switch active nav group on the sidebar
      function switchNavGroup(groupId, targetPage) {
        if (!navGroups[groupId]) return;
        activeNavGroup = groupId;
        
        document.querySelectorAll('.nav-group-item').forEach(el => {
          el.classList.toggle('active', el.dataset.group === groupId);
        });

        const grp = navGroups[groupId];
        const pageToSwitch = targetPage || grp.defaultPage;
        renderSubnavPills();
        switchPage(pageToSwitch);
      }

      // Render the horizontal sub-nav pills for the active 5-group tab
      function renderSubnavPills() {
        const strip = document.getElementById('workspace-subnav-strip');
        if (!strip) return;
        strip.replaceChildren();

        const grp = navGroups[activeNavGroup] || navGroups["group-posture"];
        
        // Group title tag
        const tag = document.createElement('span');
        tag.className = 'badge purple';
        tag.textContent = `${grp.icon} ${grp.title}`;
        strip.appendChild(tag);

        grp.pages.forEach(pg => {
          const pill = document.createElement('button');
          pill.className = `subnav-pill ${pg === activePageName ? 'active' : ''}`;
          pill.textContent = pg;
          pill.onclick = () => switchPage(pg);
          strip.appendChild(pill);
        });
      }

      // Find which group contains a given page name
      function findGroupForPage(pageName) {
        for (const [gid, grp] of Object.entries(navGroups)) {
          if (grp.pages.includes(pageName)) return gid;
        }
        return "group-posture";
      }

      // Auth tab switching
      function switchAuthTab(tab) {
        document.getElementById('btn-auth-tab-login').classList.toggle('active', tab === 'login');
        document.getElementById('btn-auth-tab-register').classList.toggle('active', tab === 'register');
        document.getElementById('auth-login-form').style.display = (tab === 'login') ? 'block' : 'none';
        document.getElementById('auth-register-form').style.display = (tab === 'register') ? 'block' : 'none';
      }

      function fillDemoOperator() {
        document.getElementById('auth-login-email').value = "operator.alpha@soc.defense.gov";
        document.getElementById('auth-login-pass').value = "CNSA2-Quantum-Safe!99";
        document.getElementById('auth-login-clearance').value = "Level 5: Top Secret / CNSA 2.0 Clearance";
      }

      function handleOperatorLogin(e) {
        e.preventDefault();
        const email = document.getElementById('auth-login-email').value;
        const tier = document.getElementById('auth-login-clearance').value;
        const shortName = email.split('@')[0];
        
        localStorage.setItem('ipsec_session', JSON.stringify({ name: shortName, tier }));
        updateOperatorUI(shortName, tier);
        showView('workspace');
      }

      function handleOperatorRegister(e) {
        e.preventDefault();
        const name = document.getElementById('auth-reg-name').value;
        const tier = document.getElementById('auth-reg-clearance').value;
        
        localStorage.setItem('ipsec_session', JSON.stringify({ name, tier }));
        updateOperatorUI(name, tier);
        showView('workspace');
      }

      function updateOperatorUI(name, tier) {
        const topName = document.getElementById('topbar-operator-name');
        const topTier = document.getElementById('topbar-operator-tier');
        if (topName) topName.textContent = name || "Operator Jane";
        if (topTier) topTier.textContent = tier ? tier.split(':')[0] : "Level 5 (CNSA)";
      }

      function calculatePassEntropy(val) {
        const fill = document.getElementById('pass-entropy-fill');
        const txt = document.getElementById('pass-entropy-text');
        if (!fill || !txt) return;
        const len = val.length;
        let score = Math.min(100, len * 8);
        if (/[A-Z]/.test(val) && /[0-9]/.test(val) && /[^A-Za-z0-9]/.test(val)) score = Math.min(100, score + 25);
        fill.style.width = `${score}%`;
        if (score < 40) {
          fill.style.backgroundColor = 'var(--red)';
          txt.textContent = 'Weak Passphrase — Minimum 12 characters recommended';
        } else if (score < 75) {
          fill.style.backgroundColor = 'var(--amber)';
          txt.textContent = 'Moderate Entropy — Add uppercase & symbols';
        } else {
          fill.style.backgroundColor = 'var(--green)';
          txt.textContent = 'NIST SP 800-63B Compliant Strong Entropy';
        }
      }

      // Landing simulator teaser
      function updateLandingScoreSimulator() {
        const cipher = document.getElementById('landing-sim-cipher').value;
        const dh = document.getElementById('landing-sim-dh').value;
        const pfs = document.getElementById('landing-sim-pfs').checked;
        const scoreEl = document.getElementById('landing-sim-score');
        const verdictEl = document.getElementById('landing-sim-verdict');
        const badgeEl = document.getElementById('landing-sim-badge');

        let score = 50;
        if (cipher === 'aes256_gcm') score += 30;
        else if (cipher === 'aes128_gcm') score += 25;
        else if (cipher === 'aes256_cbc') score += 15;
        else if (cipher === '3des_cbc') score -= 25;
        else if (cipher === 'des_cbc') score -= 45;

        if (dh === 'curve25519' || dh === 'ecp384') score += 15;
        else if (dh === 'modp2048') score += 10;
        else if (dh === 'modp1024') score -= 30;

        if (pfs) score += 5; else score -= 10;
        score = Math.max(0, Math.min(100, score));

        scoreEl.textContent = `${score} / 100`;
        if (score >= 85) {
          badgeEl.className = "badge success";
          badgeEl.textContent = "EXCELLENT · CNSA 2.0";
          verdictEl.textContent = "Full NIST SP 800-77 & NSA CNSA 2.0 Compliance. Authenticated AEAD with modern Elliptic Curve Key Exchange.";
        } else if (score >= 60) {
          badgeEl.className = "badge warning";
          badgeEl.textContent = "ACCEPTABLE · LEGACY";
          verdictEl.textContent = "Meets baseline NIST requirements but lacks post-quantum readiness and authenticated AEAD encryption.";
        } else {
          badgeEl.className = "badge danger";
          badgeEl.textContent = "VULNERABLE · EXPOSED";
          verdictEl.textContent = "Critical cryptographic exposure (CVE-2016-2183 / CVE-2015-4000). Immediate cipher upgrade required!";
        }
      }

""" + existing_js + """
    </script>
  </body>
</html>
"""

with open("frontend/index.html", "w", encoding="utf-8") as f:
    f.write(new_html)

print("SUCCESS: Generated updated frontend/index.html with 5 grouped tabs, landing page, and auth portal!")
