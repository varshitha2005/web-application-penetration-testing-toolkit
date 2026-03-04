from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf_report(data):
    doc = SimpleDocTemplate("static/report.pdf")
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("Web Pentest Report", styles['Title']))
    elements.append(Spacer(1, 12))

    for key, value in data.items():
        elements.append(Paragraph(f"{key}: {value}", styles['Normal']))
        elements.append(Spacer(1, 8))

    doc.build(elements)
    return "static/report.pdf"