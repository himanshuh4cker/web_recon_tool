"""HTML report generation module for web recon findings."""

from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Dict, List


def _render_subdomains(subdomain_data: Dict) -> str:
    """Render subdomain findings as an HTML table."""
    entries = subdomain_data.get("unique_subdomains", [])
    if not entries:
        return "<p>No subdomains discovered.</p>"

    rows = []
    for idx, sub in enumerate(entries, start=1):
        rows.append(f"<tr><td>{idx}</td><td>{escape(sub)}</td></tr>")

    return (
        "<table><thead><tr><th>#</th><th>Subdomain</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _render_ports(portscan_data: Dict) -> str:
    """Render open ports with service/version details as an HTML table."""
    ports = portscan_data.get("open_ports", [])
    if not ports:
        return "<p>No open ports found or scan failed.</p>"

    rows = []
    for item in ports:
        service_full = " ".join(
            [
                item.get("service", ""),
                item.get("product", ""),
                item.get("version", ""),
                item.get("extrainfo", ""),
            ]
        ).strip()
        rows.append(
            "<tr>"
            f"<td>{escape(str(item.get('host', '')))}</td>"
            f"<td>{escape(str(item.get('port', '')))}</td>"
            f"<td>{escape(str(item.get('protocol', '')))}</td>"
            f"<td>{escape(str(item.get('state', '')))}</td>"
            f"<td>{escape(service_full)}</td>"
            "</tr>"
        )

    return (
        "<table><thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>State</th><th>Service</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _render_headers(headers_data: Dict) -> str:
    """Render security headers analysis and highlight missing headers."""
    headers = headers_data.get("headers", {})
    if not headers:
        return "<p>No headers data available.</p>"

    rows = []
    for header_name, values in headers.items():
        present = values.get("present", False)
        status = "Present" if present else "Missing"
        class_name = "ok" if present else "missing"
        header_value = values.get("value", "")

        rows.append(
            "<tr>"
            f"<td>{escape(header_name)}</td>"
            f"<td class=\"{class_name}\">{escape(status)}</td>"
            f"<td>{escape(str(header_value))}</td>"
            "</tr>"
        )

    return (
        "<table><thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _render_tech(tech_data: Dict) -> str:
    """Render detected technologies grouped by category."""
    technologies = tech_data.get("technologies", {})
    if not technologies:
        return "<p>No technologies detected.</p>"

    blocks: List[str] = []
    for category, values in technologies.items():
        items = ", ".join(escape(str(v)) for v in values)
        blocks.append(f"<tr><td>{escape(str(category))}</td><td>{items}</td></tr>")

    return (
        "<table><thead><tr><th>Category</th><th>Technologies</th></tr></thead>"
        f"<tbody>{''.join(blocks)}</tbody></table>"
    )


def _render_whois(whois_data: Dict) -> str:
    """Render WHOIS key-value details as an HTML table."""
    info = whois_data.get("whois", {})
    if not info:
        return "<p>No WHOIS data available.</p>"

    rows = []
    for key, value in sorted(info.items(), key=lambda x: str(x[0])):
        if isinstance(value, list):
            display = ", ".join(escape(str(v)) for v in value)
        else:
            display = escape(str(value))
        rows.append(f"<tr><td>{escape(str(key))}</td><td>{display}</td></tr>")

    return (
        "<table><thead><tr><th>Field</th><th>Value</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def generate_html_report(domain: str, findings: Dict) -> str:
    """Build a complete HTML report containing all recon findings."""
    created = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    subdomains_section = _render_subdomains(findings.get("subdomain", {}))
    ports_section = _render_ports(findings.get("portscan", {}))
    headers_section = _render_headers(findings.get("headers", {}))
    tech_section = _render_tech(findings.get("techdetect", {}))
    whois_section = _render_whois(findings.get("whois_lookup", {}))

    return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
  <title>Web Recon Report - {escape(domain)}</title>
  <style>
    body {{
      margin: 0;
      padding: 0;
      font-family: Arial, sans-serif;
      background: #f5f7fb;
      color: #1f2937;
    }}
    .container {{
      width: 92%;
      max-width: 1200px;
      margin: 24px auto;
      background: #ffffff;
      border-radius: 10px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);
      overflow: hidden;
    }}
    header {{
      background: #0b3d91;
      color: #ffffff;
      padding: 24px;
    }}
    header h1 {{
      margin: 0;
      font-size: 1.8rem;
    }}
    header p {{
      margin: 8px 0 0;
      font-size: 0.95rem;
      opacity: 0.95;
    }}
    section {{
      padding: 20px 24px;
      border-bottom: 1px solid #e5e7eb;
    }}
    section:last-child {{
      border-bottom: none;
    }}
    h2 {{
      margin-top: 0;
      color: #0f172a;
      font-size: 1.25rem;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.95rem;
    }}
    th, td {{
      border: 1px solid #d1d5db;
      padding: 10px;
      text-align: left;
      vertical-align: top;
      word-break: break-word;
    }}
    th {{
      background: #eef2ff;
    }}
    .missing {{
      background: #ffe4e6;
      color: #9f1239;
      font-weight: 700;
    }}
    .ok {{
      background: #dcfce7;
      color: #166534;
      font-weight: 700;
    }}
    .error {{
      color: #b91c1c;
      font-weight: 700;
    }}
    @media (max-width: 768px) {{
      header h1 {{
        font-size: 1.35rem;
      }}
      th, td {{
        font-size: 0.85rem;
        padding: 8px;
      }}
      section {{
        padding: 16px;
      }}
    }}
  </style>
</head>
<body>
  <div class=\"container\">
    <header>
      <h1>Web Recon Report</h1>
      <p>Target: {escape(domain)}<br/>Generated: {escape(created)}</p>
    </header>

    <section>
      <h2>Subdomains</h2>
      {subdomains_section}
    </section>

    <section>
      <h2>Open Ports</h2>
      {ports_section}
    </section>

    <section>
      <h2>HTTP Security Headers</h2>
      {headers_section}
    </section>

    <section>
      <h2>Technology Stack</h2>
      {tech_section}
    </section>

    <section>
      <h2>WHOIS Information</h2>
      {whois_section}
    </section>
  </div>
</body>
</html>
"""
