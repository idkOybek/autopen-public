# core/report_html.py
import json
import pathlib
import html
import datetime
from collections import Counter
from typing import List, Dict, Any


def load_findings(merge_file: pathlib.Path) -> List[Dict[str, Any]]:
    """
    Читает NDJSON с findings и возвращает список словарей.
    """
    items: List[Dict[str, Any]] = []
    if merge_file.exists():
        with merge_file.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except Exception:
                    # пропускаем кривые строки
                    pass
    return items


def _norm_severity(s: Any) -> str:
    if not s:
        return "unknown"
    s = str(s).strip().lower()
    if s in ("informational", "info"):
        return "info"
    return s


def render_html(run_id: str, findings: List[Dict[str, Any]]) -> str:
    """
    Рендерит HTML-отчёт:
      - Executive summary с инфографикой (для начальства),
      - навигация по хостам (sidebar),
      - блоки по каждому хосту (для сисадминов),
      - фильтры по severity, инструменту и тексту.
    """
    severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
    sev_rank = {name: idx for idx, name in enumerate(severity_order)}
    sev_colors = {
        "critical": "#b91c1c",
        "high": "#ef4444",
        "medium": "#f97316",
        "low": "#22c55e",
        "info": "#3b82f6",
        "unknown": "#6b7280",
    }

    total_findings = len(findings)
    sev_counts: Counter = Counter()
    tool_counts: Counter = Counter()

    # Группировка по хостам
    hosts: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        asset = f.get("asset") or "unknown"
        asset = str(asset)
        sev = _norm_severity(f.get("severity"))
        tool = str(f.get("tool") or "unknown")

        sev_counts[sev] += 1
        tool_counts[tool] += 1

        if asset not in hosts:
            hosts[asset] = {
                "asset": asset,
                "findings": [],
                "sev_counts": Counter(),
            }
        hosts[asset]["findings"].append(f)
        hosts[asset]["sev_counts"][sev] += 1

    total_assets = len(hosts)

    # худшая критичность по всему отчёту
    worst_global = "unknown"
    for name in severity_order:
        if sev_counts.get(name):
            worst_global = name
            break

    # donut chart (круговая диаграмма) — считаем проценты по severity
    donut_gradient = "#e5e7eb"
    if total_findings > 0:
        segments = []
        acc = 0.0
        for name in severity_order:
            count = sev_counts.get(name, 0)
            if not count:
                continue
            start = acc
            acc += (count / total_findings) * 100.0
            color = sev_colors.get(name, "#6b7280")
            segments.append(f"{color} {start:.1f}% {acc:.1f}%")
        if segments:
            donut_gradient = f"conic-gradient({', '.join(segments)})"

    # список инструментов (для фильтра)
    tools_sorted = sorted(tool_counts.keys(), key=lambda x: x.lower()) if tool_counts else []

    # helper: id для якоря по хосту
    def host_id(asset: str) -> str:
        safe = "".join(ch if ch.isalnum() else "-" for ch in asset)
        safe = safe.strip("-") or "host"
        return f"host-{safe}"

    # sidebar hosts (папочная структура)
    def render_host_sidebar() -> str:
        # сортируем хосты по худшей критичности и количеству находок
        def host_sort_key(item):
            asset, data = item
            counts = data["sev_counts"]
            worst = "unknown"
            for name in severity_order:
                if counts.get(name):
                    worst = name
                    break
            rank = sev_rank.get(worst, len(severity_order))
            total = sum(counts.values())
            return (rank, -total, asset.lower())

        parts = []
        for asset, data in sorted(hosts.items(), key=host_sort_key):
            counts = data["sev_counts"]
            total = sum(counts.values())
            badge_pieces = []
            for name in severity_order:
                c = counts.get(name, 0)
                if c:
                    badge_pieces.append(f"{name[0].upper()}:{c}")
            badge = ", ".join(badge_pieces) if badge_pieces else "no issues"
            parts.append(
                f'<a class="host-link" href="#{host_id(asset)}">'
                f'<div class="host-link-line">'
                f'<span class="host-link-name">{html.escape(asset)}</span>'
                f'<span class="host-link-meta">{html.escape(badge)} · total: {total}</span>'
                f"</div></a>"
            )
        if not parts:
            return '<div class="sidebar-empty">Нет хостов</div>'
        return "".join(parts)

    # host sections
    def render_host_sections() -> str:
        sections = []
        for asset, data in sorted(hosts.items(), key=lambda kv: kv[0].lower()):
            counts = data["sev_counts"]
            total = sum(counts.values())

            worst = "unknown"
            for name in severity_order:
                if counts.get(name):
                    worst = name
                    break

            sev_summary_parts = []
            for name in severity_order:
                c = counts.get(name, 0)
                if c:
                    sev_summary_parts.append(
                        f'<span class="sev-badge sev-{name}">{html.escape(name.upper())}: {c}</span>'
                    )
            sev_summary = " ".join(sev_summary_parts) if sev_summary_parts else "Нет находок"

            # сортируем находки по severity, потом по summary
            host_findings = list(data["findings"])

            def f_sort_key(f):
                sev = _norm_severity(f.get("severity"))
                rank = sev_rank.get(sev, len(severity_order))
                return (
                    rank,
                    str(f.get("summary") or ""),
                )

            host_findings.sort(key=f_sort_key)

            # строки таблицы
            rows = []
            for f in host_findings:
                sev = _norm_severity(f.get("severity"))
                sev_color = sev_colors.get(sev, "#6b7280")
                sev_html = (
                    f'<span class="sev-pill" style="background:{sev_color};">'
                    f'{html.escape(sev.upper())}</span>'
                )

                raw_tool = str(f.get("tool") or "")
                tool_cell = html.escape(raw_tool)

                summary = html.escape(str(f.get("summary") or ""))

                # локация: порт / url / путь
                loc_bits = []
                port = f.get("port")
                proto = f.get("proto") or "tcp"
                url = f.get("url")
                path = f.get("path")
                if port:
                    loc_bits.append(f"{port}/{proto}")
                if url:
                    loc_bits.append(str(url))
                elif path:
                    loc_bits.append(str(path))
                location_str = " · ".join(loc_bits) if loc_bits else "—"
                location_cell = html.escape(location_str) if location_str != "—" else location_str

                # remediation: либо из поля, либо заглушка
                remediation = str(f.get("remediation") or "").strip()
                if remediation:
                    remediation_html = html.escape(remediation)
                else:
                    remediation_html = (
                        "Шаги к устранению для этой проблемы "
                        "следует описать вручную в этом блоке."
                    )
                remediation_html = (
                    f'<div class="editable-block remediation-block">{remediation_html}</div>'
                )

                extra_bits = []
                cve = f.get("cve")
                cwe = f.get("cwe")
                template_id = f.get("template_id") or f.get("id")
                if cve:
                    extra_bits.append(f"CVE: {str(cve)}")
                if cwe:
                    extra_bits.append(f"CWE: {str(cwe)}")
                if template_id:
                    extra_bits.append(f"ID: {str(template_id)}")
                extra_str = " · ".join(extra_bits) if extra_bits else ""
                extra_html = html.escape(extra_str) if extra_str else "—"

                # текст для поиска
                filter_text = " ".join(
                    [
                        asset,
                        sev,
                        raw_tool,
                        str(f.get("summary") or ""),
                        location_str,
                        extra_str,
                    ]
                ).lower()
                filter_text_attr = html.escape(filter_text, quote=True)
                sev_attr = html.escape(sev, quote=True)
                tool_attr = html.escape(raw_tool, quote=True)

                rows.append(
                    "<tr "
                    f'class="finding-row" '
                    f'data-sev="{sev_attr}" '
                    f'data-tool="{tool_attr}" '
                    f'data-text="{filter_text_attr}">'
                    f"<td>{sev_html}</td>"
                    f"<td>{location_cell}</td>"
                    f"<td>{summary}</td>"
                    f"<td>{remediation_html}</td>"
                    f"<td>{tool_cell}<br/><span class=\"extra-meta\">{extra_html}</span></td>"
                    "</tr>"
                )

            rows_html = "".join(rows) if rows else (
                '<tr><td colspan="5" class="no-findings">Нет находок для этого хоста</td></tr>'
            )

            sections.append(
                f"""
<section class="host-section" id="{host_id(asset)}">
  <h2 class="host-title">{html.escape(asset)}</h2>
  <div class="host-summary">
    <div class="host-summary-line">
      <span class="host-summary-label">Итого находок:</span>
      <span class="host-summary-value">{total}</span>
    </div>
    <div class="host-summary-line">
      <span class="host-summary-label">Худшая критичность:</span>
      <span class="host-summary-value">{html.escape(worst.upper())}</span>
    </div>
    <div class="host-summary-sev">
      {sev_summary}
    </div>
  </div>

  <table class="host-table">
    <thead>
      <tr>
        <th>Severity</th>
        <th>Сервис / URL</th>
        <th>Описание</th>
        <th>Шаги к устранению</th>
        <th>Источник / детали</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</section>
"""
            )
        return "\n".join(sections) if sections else """
<section class="host-section">
  <h2 class="host-title">Нет данных по хостам</h2>
  <p>Скан не обнаружил ни одной записи.</p>
</section>
"""

    # summary по инструментам
    def render_tools_summary() -> str:
        if not tool_counts:
            return "<div class=\"tools-empty\">Нет данных по инструментам.</div>"
        items = []
        for tool, count in sorted(tool_counts.items(), key=lambda kv: kv[0].lower()):
            items.append(
                f"<div class=\"tool-line\"><span class=\"tool-name\">"
                f"{html.escape(tool)}</span><span class=\"tool-count\">{count}</span></div>"
            )
        return "".join(items)

    generated_ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    worst_global_color = sev_colors.get(worst_global, "#6b7280")

    # бейджи по severity для summary
    sev_chips = []
    for name in severity_order:
        c = sev_counts.get(name, 0)
        if not c:
            continue
        sev_chips.append(
            f'<span class="sev-chip">'
            f'<span class="sev-chip-color" style="background:{sev_colors.get(name, "#6b7280")};"></span>'
            f'<span class="sev-chip-label">{html.escape(name.upper())}: {c}</span>'
            f"</span>"
        )
    sev_chips_html = "".join(sev_chips) if sev_chips else "Нет находок"

    host_sidebar_html = render_host_sidebar()
    host_sections_html = render_host_sections()
    tools_summary_html = render_tools_summary()

    # опции инструментов для фильтра
    if tools_sorted:
        tool_options_html = (
            '<option value="all">Все</option>'
            + "".join(
                f'<option value="{html.escape(t, quote=True)}">{html.escape(t)}</option>'
                for t in tools_sorted
            )
        )
    else:
        tool_options_html = '<option value="all">Все</option>'

    html_str = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8"/>
<title>Autopen report - {html.escape(run_id)}</title>
<style>
  :root {{
    --bg: #f3f4f6;
    --sidebar-bg: #111827;
    --sidebar-fg: #e5e7eb;
    --accent: #2563eb;
    --card-bg: #ffffff;
    --card-border: #e5e7eb;
    --text-main: #111827;
    --text-muted: #6b7280;
  }}

  * {{
    box-sizing: border-box;
  }}

  body {{
    margin: 0;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: var(--bg);
    color: var(--text-main);
  }}

  .layout {{
    display: flex;
    min-height: 100vh;
  }}

  .sidebar {{
    width: 260px;
    background: var(--sidebar-bg);
    color: var(--sidebar-fg);
    padding: 16px 14px 24px;
    position: fixed;
    top: 0;
    bottom: 0;
    left: 0;
    overflow-y: auto;
  }}

  .sidebar-title {{
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #9ca3af;
    margin-bottom: 10px;
  }}

  .host-link {{
    display: block;
    text-decoration: none;
    color: inherit;
  }}

  .host-link-line {{
    padding: 6px 8px;
    border-radius: 6px;
    margin-bottom: 4px;
    transition: background 0.15s ease;
  }}

  .host-link-line:hover {{
    background: rgba(55, 65, 81, 0.7);
  }}

  .host-link-name {{
    font-size: 13px;
    font-weight: 600;
    display: block;
  }}

  .host-link-meta {{
    font-size: 11px;
    color: #9ca3af;
    display: block;
    margin-top: 1px;
  }}

  .sidebar-empty {{
    font-size: 12px;
    color: #9ca3af;
  }}

  .content {{
    margin-left: 260px;
    padding: 20px 32px 32px;
  }}

  .topbar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 18px;
  }}

  .title-block h1 {{
    margin: 0;
    font-size: 22px;
    font-weight: 700;
  }}

  .title-block .meta {{
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 4px;
  }}

  .topbar-buttons {{
    display: flex;
    gap: 8px;
  }}

  .btn {{
    font-size: 12px;
    padding: 6px 10px;
    border-radius: 6px;
    border: 1px solid #d1d5db;
    background: #f9fafb;
    cursor: pointer;
  }}

  .btn-primary {{
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
  }}

  .btn:hover {{
    filter: brightness(0.97);
  }}

  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    margin-bottom: 18px;
  }}

  .card {{
    background: var(--card-bg);
    border-radius: 10px;
    border: 1px solid var(--card-border);
    padding: 10px 12px;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
  }}

  .card-title {{
    font-size: 11px;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 4px;
  }}

  .card-value {{
    font-size: 18px;
    font-weight: 700;
  }}

  .card-sub {{
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 2px;
  }}

  .risk-badge {{
    display: inline-flex;
    align-items: center;
    font-size: 12px;
    padding: 2px 8px;
    border-radius: 999px;
    background: rgba(239, 68, 68, 0.08);
    color: {worst_global_color};
    border: 1px solid rgba(239, 68, 68, 0.4);
    gap: 4px;
  }}

  .sev-dot {{
    width: 8px;
    height: 8px;
    border-radius: 999px;
    background: {worst_global_color};
  }}

  .donut-wrap {{
    display: flex;
    align-items: center;
    gap: 14px;
  }}

  .donut {{
    width: 88px;
    height: 88px;
    border-radius: 999px;
    background: {donut_gradient};
    display: flex;
    align-items: center;
    justify-content: center;
  }}

  .donut-inner {{
    width: 52px;
    height: 52px;
    border-radius: 999px;
    background: #f9fafb;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 14px;
    font-weight: 700;
  }}

  .sev-legend {{
    display: flex;
    flex-direction: column;
    gap: 2px;
    font-size: 11px;
  }}

  .sev-chip {{
    display: inline-flex;
    align-items: center;
    margin-right: 6px;
    margin-bottom: 2px;
  }}

  .sev-chip-color {{
    width: 8px;
    height: 8px;
    border-radius: 999px;
    margin-right: 4px;
  }}

  .sev-chip-label {{
    font-size: 11px;
  }}

  .editable-block {{
    border-radius: 6px;
    padding: 6px 8px;
    background: #f9fafb;
    border: 1px dashed transparent;
    min-height: 20px;
  }}

  .editable-block.editing {{
    border-color: #c4b5fd;
    background: #eef2ff;
  }}

  .section-title {{
    margin: 20px 0 10px;
    font-size: 16px;
  }}

  .hosts-summary-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }}

  .hosts-summary-table th,
  .hosts-summary-table td {{
    border-bottom: 1px solid #e5e7eb;
    padding: 6px 8px;
    text-align: left;
  }}

  .hosts-summary-table th {{
    background: #f9fafb;
    font-weight: 600;
  }}

  .hosts-summary-table tr:nth-child(even) td {{
    background: #f9fafb;
  }}

  .hosts-summary-table a {{
    color: var(--accent);
    text-decoration: none;
    font-weight: 500;
  }}

  .host-section {{
    margin-top: 24px;
    page-break-inside: avoid;
  }}

  .host-title {{
    font-size: 18px;
    margin: 0 0 4px 0;
  }}

  .host-summary {{
    font-size: 12px;
    margin-bottom: 8px;
  }}

  .host-summary-line {{
    display: inline-block;
    margin-right: 16px;
  }}

  .host-summary-label {{
    color: var(--text-muted);
    margin-right: 4px;
  }}

  .host-summary-sev {{
    margin-top: 4px;
  }}

  .sev-badge {{
    display: inline-block;
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 999px;
    margin-right: 4px;
    margin-bottom: 2px;
    background: #e5e7eb;
    color: #111827;
  }}

  .host-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    margin-top: 6px;
  }}

  .host-table th,
  .host-table td {{
    border-bottom: 1px solid #e5e7eb;
    padding: 6px 8px;
    vertical-align: top;
  }}

  .host-table th {{
    background: #f9fafb;
  }}

  .host-table tr:nth-child(even) td {{
    background: #f9fafb;
  }}

  .sev-pill {{
    display: inline-block;
    padding: 2px 6px;
    border-radius: 999px;
    font-size: 11px;
    color: #ffffff;
  }}

  .extra-meta {{
    font-size: 10px;
    color: var(--text-muted);
  }}

  .no-findings {{
    text-align: center;
    color: var(--text-muted);
  }}

  .tools-summary {{
    font-size: 12px;
  }}

  .tool-line {{
    display: flex;
    justify-content: space-between;
    margin-bottom: 2px;
  }}

  .tool-name {{
    font-weight: 500;
  }}

  .tool-count {{
    color: var(--text-muted);
  }}

  .tools-empty {{
    font-size: 12px;
    color: var(--text-muted);
  }}

  .meta-note {{
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 8px;
  }}

  .filters-bar {{
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    align-items: center;
    margin: 10px 0 16px;
    font-size: 12px;
  }}

  .filters-group {{
    display: flex;
    align-items: center;
    gap: 8px;
  }}

  .filters-group label {{
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 12px;
  }}

  .filters-group input[type="checkbox"] {{
    width: 14px;
    height: 14px;
  }}

  .filters-group select,
  .filters-group input[type="text"] {{
    font-size: 12px;
    padding: 4px 6px;
    border-radius: 4px;
    border: 1px solid #d1d5db;
    background: #f9fafb;
  }}

  @media print {{
    body {{
      background: #ffffff;
    }}
    .sidebar {{
      display: none;
    }}
    .content {{
      margin-left: 0;
      padding: 10mm 12mm;
    }}
    .topbar-buttons,
    .filters-bar {{
      display: none;
    }}
    .editable-block {{
      border: none;
      background: transparent;
    }}
  }}
</style>
<script>
  function toggleEdit() {{
    var blocks = document.querySelectorAll('.editable-block');
    if (!blocks.length) return;
    var editing = blocks[0].isContentEditable;
    var nextState = !editing;
    blocks.forEach(function(b) {{
      b.contentEditable = nextState ? "true" : "false";
      if (nextState) {{
        b.classList.add('editing');
      }} else {{
        b.classList.remove('editing');
      }}
    }});
    var btn = document.getElementById('edit-toggle');
    if (btn) {{
      btn.textContent = nextState ? 'Выключить редактирование' : 'Включить редактирование';
    }}
  }}

  function triggerPrint() {{
    window.print();
  }}

  function applyFilters() {{
    var activeSev = new Set();
    document.querySelectorAll('.sev-filter-checkbox').forEach(function(cb) {{
      if (cb.checked) {{
        activeSev.add(cb.value);
      }}
    }});

    var toolSelect = document.getElementById('tool-filter');
    var toolValue = toolSelect ? toolSelect.value : 'all';

    var textInput = document.getElementById('text-filter');
    var textValue = textInput ? textInput.value.toLowerCase().trim() : '';

    var rows = document.querySelectorAll('tr.finding-row');
    rows.forEach(function(row) {{
      var sev = row.getAttribute('data-sev') || 'unknown';
      var tool = row.getAttribute('data-tool') || '';
      var text = row.getAttribute('data-text') || '';

      var ok = true;

      if (activeSev.size && !activeSev.has(sev)) {{
        ok = false;
      }}

      if (ok && toolValue && toolValue !== 'all' && tool !== toolValue) {{
        ok = false;
      }}

      if (ok && textValue && !text.includes(textValue)) {{
        ok = false;
      }}

      row.style.display = ok ? '' : 'none';
    }});
  }}

  document.addEventListener('DOMContentLoaded', function() {{
    document.querySelectorAll('.sev-filter-checkbox').forEach(function(cb) {{
      cb.addEventListener('change', applyFilters);
    }});
    var toolSelect = document.getElementById('tool-filter');
    if (toolSelect) {{
      toolSelect.addEventListener('change', applyFilters);
    }}
    var textInput = document.getElementById('text-filter');
    if (textInput) {{
      textInput.addEventListener('input', function() {{
        applyFilters();
      }});
    }}
    applyFilters();
  }});
</script>
</head>
<body>
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-title">Hosts</div>
    {host_sidebar_html}
  </aside>
  <main class="content">
    <div class="topbar">
      <div class="title-block">
        <h1>Autopen Security Report</h1>
        <div class="meta">
          Run ID: <b>{html.escape(run_id)}</b> · Generated: {generated_ts}
        </div>
      </div>
      <div class="topbar-buttons">
        <button class="btn" id="edit-toggle" onclick="toggleEdit()">Включить редактирование</button>
        <button class="btn btn-primary" onclick="triggerPrint()">Печать / PDF</button>
      </div>
    </div>

    <section>
      <div class="summary-grid">
        <div class="card">
          <div class="card-title">Всего находок</div>
          <div class="card-value">{total_findings}</div>
          <div class="card-sub">Активов: {total_assets}</div>
        </div>
        <div class="card">
          <div class="card-title">Уровень риска</div>
          <div class="card-value">
            <span class="risk-badge">
              <span class="sev-dot"></span>
              {html.escape(worst_global.upper())}
            </span>
          </div>
          <div class="card-sub">Базируется на худшей критичности найденных проблем</div>
        </div>
        <div class="card">
          <div class="card-title">Распределение по severity</div>
          <div class="donut-wrap">
            <div class="donut">
              <div class="donut-inner">{total_findings}</div>
            </div>
            <div class="sev-legend">
              {sev_chips_html}
            </div>
          </div>
        </div>
        <div class="card">
          <div class="card-title">Инструменты</div>
          <div class="tools-summary">
            {tools_summary_html}
          </div>
        </div>
      </div>

      <h2 class="section-title">Executive summary</h2>
      <div class="editable-block">
        Здесь можно кратко описать общий уровень риска, основные выводы и бизнес-риски.
        Этот текст редактируется прямо в браузере после нажатия кнопки
        «Включить редактирование».
      </div>

      <h2 class="section-title">Top проблемы</h2>
      <div class="editable-block">
        Перечислите 3–5 ключевых проблем, которые в первую очередь должны быть устранены.
        Пример: "Открытые административные интерфейсы из Интернета", "Устаревшие версии ПО" и т.п.
      </div>

      <h2 class="section-title">Фильтры</h2>
      <div class="filters-bar">
        <div class="filters-group">
          <span>Severity:</span>
"""

    # чекбоксы по критичности
    for name in severity_order:
        label = name.upper()
        html_str += (
            f'<label><input type="checkbox" class="sev-filter-checkbox" '
            f'value="{html.escape(name, quote=True)}" checked> {html.escape(label)}</label>'
        )

    html_str += f"""
        </div>
        <div class="filters-group">
          <label>Инструмент:
            <select id="tool-filter">
              {tool_options_html}
            </select>
          </label>
        </div>
        <div class="filters-group">
          <label>Поиск:
            <input id="text-filter" type="text" placeholder="фильтр по описанию, сервису, CVE..." />
          </label>
        </div>
      </div>

      <h2 class="section-title">Обзор по хостам</h2>
      <table class="hosts-summary-table">
        <thead>
          <tr>
            <th>Хост</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
            <th>Info</th>
            <th>Всего</th>
            <th>Детали</th>
          </tr>
        </thead>
        <tbody>
"""

    # overview по хостам
    overview_rows = []
    for asset, data in sorted(hosts.items(), key=lambda kv: kv[0].lower()):
        counts = data["sev_counts"]
        total = sum(counts.values())
        c_vals = {name: counts.get(name, 0) for name in severity_order}
        overview_rows.append(
            "<tr>"
            f"<td>{html.escape(asset)}</td>"
            f"<td>{c_vals['critical']}</td>"
            f"<td>{c_vals['high']}</td>"
            f"<td>{c_vals['medium']}</td>"
            f"<td>{c_vals['low']}</td>"
            f"<td>{c_vals['info']}</td>"
            f"<td>{total}</td>"
            f'<td><a href="#{host_id(asset)}">Открыть</a></td>'
            "</tr>"
        )
    if not overview_rows:
        overview_rows_html = (
            '<tr><td colspan="8" class="no-findings">'
            "Нет хостов для отображения</td></tr>"
        )
    else:
        overview_rows_html = "".join(overview_rows)

    html_str += overview_rows_html

    html_str += f"""
        </tbody>
      </table>
      <div class="meta-note">
        Примечание: клики по ссылкам в колонке "Детали" переводят к соответствующему блоку хоста.
        Фильтры выше (severity, инструмент, поиск) применяются ко всем таблицам ниже.
      </div>
    </section>

    {host_sections_html}

  </main>
</div>
</body>
</html>
"""

    return html_str
