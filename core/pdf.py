from weasyprint import HTML

def html_to_pdf(html_path, pdf_path):
    # минимальный вызов из официального примера
    HTML(filename=str(html_path)).write_pdf(str(pdf_path))
