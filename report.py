"""PDF report generation using fpdf (exact TRD dependency, not ReportLab)."""
from fpdf import FPDF

PAGE_WIDTH = 190


def _safe(text):
    """fpdf 1.7.2 only supports Latin-1 output."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


def build_report_pdf(scan):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(PAGE_WIDTH, 12, "WebSecure Security Report", ln=1)

    pdf.set_font("Helvetica", "", 11)
    pdf.cell(PAGE_WIDTH, 8, _safe(f"Target: {scan.target_url}"), ln=1)
    pdf.cell(PAGE_WIDTH, 8, _safe(f"Scanned: {scan.scan_date.strftime('%Y-%m-%d %H:%M UTC')}"), ln=1)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(PAGE_WIDTH, 10, _safe(f"Score: {scan.security_score}/100  -  Header hardening: {scan.risk_level}"), ln=1)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(PAGE_WIDTH, 6, "This score rates the security headers of one page. It is not a full security audit and does not mean the site is vulnerable.")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(PAGE_WIDTH, 8, "Findings", ln=1)
    pdf.ln(2)

    for finding in scan.findings:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(
            PAGE_WIDTH, 7,
            _safe(f"{finding.header_name} - {finding.status} ({finding.severity})"),
            ln=1,
        )
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(PAGE_WIDTH, 6, _safe(finding.description))
        pdf.multi_cell(PAGE_WIDTH, 6, _safe(f"Recommendation: {finding.recommendation}"))
        pdf.ln(3)

    return bytes(pdf.output(dest="S").encode("latin-1"))
