from fpdf import FPDF
import datetime
import os

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 14)
        self.cell(0, 10, 'SQL Injection Scan Report', ln=True, align='C')
        self.set_font('Arial', '', 10)
        self.cell(0, 10, 'Generated: ' + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ln=True, align='C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

    def add_scan_result(self, data):
        self.set_font('Arial', '', 11)
        self.cell(0, 10, f"Target URL: {data['url']}", ln=True)
        self.cell(0, 10, f"Method: {data['method']}", ln=True)
        self.cell(0, 10, f"Payload Used: {data['payload']}", ln=True)
        self.cell(0, 10, f"Result: {data['result']}", ln=True)
        self.cell(0, 10, f"Timestamp: {data['timestamp']}", ln=True)
        self.ln(10)

def generate_pdf_report(scan_data, output_folder='reports'):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    pdf = PDFReport()
    pdf.add_page()
    pdf.add_scan_result(scan_data)

    filename = f"ScanReport_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(output_folder, filename)
    pdf.output(filepath)
    return filepath
