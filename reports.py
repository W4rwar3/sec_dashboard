from fpdf import FPDF
import pandas as pd
import io
import os
import tempfile
import datetime

def generate_csv(df):
    """Generates a CSV string from the dataframe."""
    return df.to_csv(index=False).encode('utf-8')

class VAPTReport(FPDF):
    def __init__(self, project_name):
        super().__init__()
        self.project_name = project_name
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        # Logo placeholder or simple text
        self.set_font('Arial', 'B', 20)
        self.cell(0, 10, 'VAPT Security Report', ln=True, align='C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 10, f"Project: {self.project_name} | Date: {datetime.datetime.now().strftime('%Y-%m-%d')}", ln=True, align='C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 16)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 10, title, ln=True, fill=True)
        self.ln(5)

    def chapter_body(self, body):
        self.set_font('Arial', '', 12)
        self.multi_cell(0, 10, body)
        self.ln()

def generate_pdf(project_name, df, figures):
    """
    Generates a PDF report.
    figures: dict of {'name': plotly_fig}
    """
    pdf = VAPTReport(project_name)
    pdf.add_page()
    
    # 1. Executive Summary
    pdf.chapter_title("Executive Summary")
    
    total = len(df)
    critical = len(df[df['Severity'] == 'Critical'])
    high = len(df[df['Severity'] == 'High'])
    
    summary_text = (
        f"This report summarizes the findings for project '{project_name}'. "
        f"A total of {total} vulnerabilities were identified during the scan. "
        f"Critical Issues: {critical}, High Issues: {high}. "
        "Immediate attention is recommended for Critical and High severity findings."
    )
    pdf.chapter_body(summary_text)
    
    # 2. Visualizations
    pdf.chapter_title("Visual Insights")
    
    # Save figures to temp files
    temp_files = []
    try:
        current_y = pdf.get_y()
        
        # We'll try to put 2 charts per page or one big one
        for title, fig in figures.items():
            if fig:
                 with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                    # Determine dimensions based on chart type
                    # Pie charts can be smaller, Bars wider
                    # Write image
                    try:
                        fig.write_image(tmp.name, width=800, height=500, scale=2)
                        temp_files.append(tmp.name)
                        
                        if pdf.get_y() > 200: pdf.add_page()
                        
                        pdf.set_font('Arial', 'B', 12)
                        pdf.cell(0, 10, title, ln=True)
                        # Image width approx 150mm (A4 is 210mm)
                        pdf.image(tmp.name, x=15, w=180)
                        pdf.ln(5)
                    except Exception as e:
                        print(f"Error saving chart {title}: {e}")
                        pdf.cell(0, 10, f"[Chart: {title} could not be generated]", ln=True)

    finally:
        pass # Cleanup later

    # 3. Detailed Findings Table
    pdf.add_page()
    pdf.chapter_title("Detailed Findings")
    
    # Table Header
    pdf.set_font('Arial', 'B', 10)
    cols = [20, 40, 30, 100] # Widths for Severity, Name, Category, Location (Description is too long usually)
    headers = ['Sev', 'Name', 'Category', 'Location']
    
    for i, h in enumerate(headers):
        pdf.cell(cols[i], 10, h, 1)
    pdf.ln()
    
    # Table Rows
    pdf.set_font('Arial', '', 9)
    # Limit to top 50 to avoid massive PDFs for now, or just iterate all
    for _, row in df.head(100).iterrows():
        # Check page break
        if pdf.get_y() > 270:
            pdf.add_page()
            # Re-print header
            pdf.set_font('Arial', 'B', 10)
            for i, h in enumerate(headers):
                pdf.cell(cols[i], 10, h, 1)
            pdf.ln()
            pdf.set_font('Arial', '', 9)
            
        sev = str(row.get('Severity', ''))[:10]
        name = str(row.get('Name', ''))[:25] # Truncate
        cat = str(row.get('Category', ''))[:20]
        loc = str(row.get('File_Location', ''))[:60]
        
        # Color coding for severity (Optional text color)
        if sev == 'Critical': pdf.set_text_color(139, 0, 0)
        elif sev == 'High': pdf.set_text_color(255, 0, 0)
        else: pdf.set_text_color(0, 0, 0)
        
        pdf.cell(cols[0], 8, sev, 1)
        pdf.cell(cols[1], 8, name, 1)
        pdf.cell(cols[2], 8, cat, 1)
        # Multi-cell for location if needed, but simple cell for now for layout stability
        pdf.cell(cols[3], 8, loc, 1)
        pdf.ln()

    # Restoration
    pdf.set_text_color(0, 0, 0)

    # Cleanup temp files
    for f in temp_files:
        if os.path.exists(f): 
            try: os.remove(f)
            except: pass

    return pdf.output(dest='S').encode('latin-1')
