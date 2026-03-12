from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(data):

    file_path = "static/report.pdf"

    doc = SimpleDocTemplate(file_path)

    styles = getSampleStyleSheet()

    elements = []

    elements.append(Paragraph("Web Pentest Report", styles['Title']))
    elements.append(Spacer(1, 20))

    for key, value in data.items():

        elements.append(Paragraph(f"<b>{key}</b>", styles['Heading3']))
        elements.append(Spacer(1, 8))

        # Format lists nicely
        if isinstance(value, list):
            for item in value:
                elements.append(Paragraph(str(item), styles['Normal']))
                elements.append(Spacer(1, 5))

        # Format dictionaries
        elif isinstance(value, dict):
            for k, v in value.items():
                elements.append(Paragraph(f"{k}: {v}", styles['Normal']))
                elements.append(Spacer(1, 5))

        else:
            elements.append(Paragraph(str(value), styles['Normal']))
            elements.append(Spacer(1, 5))

        elements.append(Spacer(1, 10))

    doc.build(elements)

    return file_path