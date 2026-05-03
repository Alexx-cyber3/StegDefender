from fpdf import FPDF
import os
import json
import time

class ReportGenerator(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'StegDefender Forensic Report', 0, 1, 'C')
        self.line(10, 20, 200, 20)
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, body)
        self.ln()

    def add_findings_table(self, findings):
        self.set_font('Arial', 'B', 10)
        self.cell(30, 7, 'Severity', 1)
        self.cell(160, 7, 'Detail', 1)
        self.ln()
        self.set_font('Arial', '', 9)
        
        for detail in findings.get('details', []):
            severity = detail.get('severity', 'info').upper()
            msg = detail.get('message', '')
            
            # Simple color coding text
            if severity == 'DANGER':
                self.set_text_color(200, 0, 0)
            elif severity == 'WARNING':
                self.set_text_color(200, 100, 0)
            else:
                self.set_text_color(0, 0, 0)
                
            self.cell(30, 7, severity, 1)
            # Truncate msg if too long for simple cell
            self.cell(160, 7, msg[:85] + ('...' if len(msg)>85 else ''), 1)
            self.ln()
            self.set_text_color(0, 0, 0)
            
        self.ln()

    def generate(self, analysis_data, output_path):
        self.add_page()
        
        # Meta Info
        self.set_font('Arial', '', 10)
        self.cell(0, 5, f'Date: {time.strftime("%Y-%m-%d %H:%M:%S")}', 0, 1)
        self.cell(0, 5, f'File: {analysis_data.get("filename", "Unknown")}', 0, 1)
        
        risk = analysis_data.get('findings', {}).get('verdict', 'Unknown')
        self.cell(0, 5, f'Risk Verdict: {risk}', 0, 1)
        self.ln(10)

        # Recursive traversal for report
        self._add_node_to_report(analysis_data)
        
        self.output(output_path)

    def _add_node_to_report(self, node, depth=0):
        indent = "  " * depth
        prefix = f"[{depth}] "
        
        title = f"{prefix}{node.get('filename')} ({node.get('info', {}).get('mime', 'unknown')})"
        self.chapter_title(title)
        
        findings = node.get('findings', {})
        
        # Metadata
        meta_str = ""
        for k, v in findings.get('metadata', {}).items():
            meta_str += f"{k}: {v}\n"
        if meta_str:
            self.set_font('Courier', '', 8)
            self.multi_cell(0, 4, meta_str)
            self.ln(2)

        # Findings Table
        if findings.get('details'):
            self.add_findings_table(findings)
        else:
            self.set_font('Arial', 'I', 9)
            self.cell(0, 6, "No specific anomalies detected.", 0, 1)
            self.ln()

        # Recurse
        for nested in node.get('nested', []):
            self._add_node_to_report(nested.get('analysis'), depth + 1)
