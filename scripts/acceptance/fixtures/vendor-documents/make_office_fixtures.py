"""Regenerate authored synthetic Office/image-PDF evidence (not customer files).

Development-only dependencies: python-docx 1.2, openpyxl 3.1, reportlab and Pillow.
Product extraction and tests do not import these generators or require these packages.
"""
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from docx import Document
from openpyxl import Workbook
from PIL import Image, ImageDraw
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

ROOT = Path(__file__).parent
POLICY = "Model provenance is documented with provider and version."
STAMP = datetime(2026, 9, 1, tzinfo=timezone.utc)


def main():
    document = Document()
    document.core_properties.title = "Synthetic Office evidence fixture"
    document.core_properties.author = "Lightwork synthetic acceptance fixture"
    document.core_properties.created = STAMP
    document.core_properties.modified = STAMP
    document.add_heading("SYNTHETIC NORTHSTAR EVIDENCE", 0)
    document.add_paragraph(POLICY)
    table = document.add_table(rows=2, cols=2)
    table.cell(0, 0).text = "Control"
    table.cell(0, 1).text = "Statement"
    table.cell(1, 0).text = "Retention"
    table.cell(1, 1).text = "Customer data is deleted within 30 days."
    document.sections[0].header.paragraphs[0].text = "Header outside the supported body-text scope."
    document.save(ROOT / "northstar-policy.docx")

    workbook = Workbook()
    workbook.properties.creator = "Lightwork synthetic acceptance fixture"
    workbook.properties.created = STAMP.replace(tzinfo=None)
    workbook.properties.modified = STAMP.replace(tzinfo=None)
    sheet = workbook.active
    sheet.title = "Evidence & controls"
    sheet.append(["SYNTHETIC EVIDENCE", "Statement"])
    sheet.append(["Provenance", POLICY])
    sheet.append(["Retention", "Customer data is deleted within 30 days."])
    sheet.append(["Hidden fixture", "Model provenance is undisclosed."])
    sheet.row_dimensions[4].hidden = True
    workbook.save(ROOT / "northstar-policy.xlsx")

    raster = Image.new("RGB", (800, 160), "white")
    draw = ImageDraw.Draw(raster)
    draw.text((20, 30), "SYNTHETIC SCANNED EVIDENCE - NOT A CUSTOMER RECORD", fill="black")
    draw.text((20, 70), POLICY, fill="black")
    data = BytesIO()
    raster.save(data, format="PNG")
    pdf = canvas.Canvas(str(ROOT / "northstar-scan.pdf"), invariant=1)
    pdf.setTitle("Synthetic raster-only evidence fixture")
    pdf.drawImage(ImageReader(data), 30, 600, width=540, height=108)
    pdf.save()


if __name__ == "__main__":
    main()
