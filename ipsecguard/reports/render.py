from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ipsecguard.models import AnalysisArtifacts, AnalysisResult
from ipsecguard.utils import REPORTS_DIR

try:
    from weasyprint import HTML
except Exception:  # pragma: no cover - optional dependency
    HTML = None

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
ENV = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=select_autoescape(["html"]))


def _render_template(name: str, context: dict) -> str:
    template = ENV.get_template(name)
    return template.render(**context)


def render_reports(result: AnalysisResult) -> AnalysisArtifacts:
    executive_id = uuid4().hex
    technical_id = uuid4().hex
    context = {
        "result": result.to_dict(),
        "findings": [finding.to_dict() for finding in result.findings],
        "session_summary": result.session_summary,
        "compliance": result.compliance,
        "remediations": result.remediations,
        "flow_statistics": result.flow_statistics,
        "threat_intel": result.threat_intel,
        "quantum_resilience": result.quantum_resilience,
    }
    executive_html = _render_template("executive.html", context)
    technical_html = _render_template("technical.html", context)
    executive_path = REPORTS_DIR / f"{executive_id}-executive.html"
    technical_path = REPORTS_DIR / f"{technical_id}-technical.html"
    executive_path.write_text(executive_html, encoding="utf-8")
    technical_path.write_text(technical_html, encoding="utf-8")
    if HTML is not None:
        HTML(string=executive_html, base_url=str(TEMPLATE_DIR)).write_pdf(
            REPORTS_DIR / f"{executive_id}-executive.pdf"
        )
        HTML(string=technical_html, base_url=str(TEMPLATE_DIR)).write_pdf(
            REPORTS_DIR / f"{technical_id}-technical.pdf"
        )
    return AnalysisArtifacts(executive_report_id=executive_id, technical_report_id=technical_id)
