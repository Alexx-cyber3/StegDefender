import os
import time
from stegdefender.core.file_identifier import FileIdentifier
from stegdefender.analyzers.image_analyzer import ImageAnalyzer
from stegdefender.analyzers.generic_analyzer import GenericAnalyzer
from stegdefender.analyzers.pdf_analyzer import PDFAnalyzer
from stegdefender.analyzers.audio_analyzer import AudioAnalyzer
from stegdefender.analyzers.archive_analyzer import ArchiveAnalyzer
from stegdefender.analyzers.network_analyzer import NetworkAnalyzer
from stegdefender.analyzers.text_analyzer import TextAnalyzer
from stegdefender.utils.yara_scanner import YaraScanner
from stegdefender.utils.vt_scanner import VTScanner
from stegdefender.utils.entropy import calculate_entropy_chunks

class ForensicEngine:
    def __init__(self, max_depth=3):
        self.max_depth = max_depth
        self.results_tree = []

    def run(self, file_path, depth=0):
        """
        Recursively analyzes a file and its extracted artifacts.
        """
        if depth > self.max_depth:
            return None

        # 1. Identify File
        try:
            file_info = FileIdentifier.identify(file_path)
            mime = file_info['mime']
        except Exception as e:
            # Fallback
            file_info = {'mime': 'application/octet-stream', 'extension': 'unknown'}
            mime = 'application/octet-stream'

        # 2. Select Analyzer
        analyzer = self._get_analyzer(mime, file_path)
        
        # 3. Analyze
        # print(f"[{depth}] Analyzing: {os.path.basename(file_path)} ({mime})") # Removed noisy print
        try:
            analysis_results = analyzer.analyze()
        except Exception as e:
            analysis_results = {
                "verdict": "Error",
                "confidence": 0,
                "details": [{"message": f"Analyzer failed: {str(e)}", "severity": "warning"}],
                "metadata": {},
                "artifacts": []
            }
        
        # 4. Scan extracted data with YARA (on the file content itself)
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
            
            # VirusTotal Scan (Simulated)
            vt_summary = VTScanner.get_analysis_summary(raw_data)
            analysis_results["details"].append({
                "message": f"Global Intel: {vt_summary}",
                "severity": "danger" if "Match!" in vt_summary else "info"
            })

            yara_matches = YaraScanner.scan(raw_data)
            for match in yara_matches:
                analysis_results["details"].append({
                    "message": f"YARA Match: {match['name']} - {match['description']}",
                    "severity": match['severity']
                })
                # Escalate verdict
                if match['severity'] == 'danger':
                    analysis_results["verdict"] = "Stego Detected"

            # 6. Telemetry Data for UI
            telemetry = {
                "entropy_map": calculate_entropy_chunks(raw_data, target_chunks=150)
            }
        except Exception as e:
             # Handle read errors (e.g. locked files)
             telemetry = {}
             analysis_results["details"].append({"message": f"Read error for extended analysis: {e}", "severity": "warning"})

        # 7. Recursive Step
        current_node = {
            "filename": os.path.basename(file_path),
            "depth": depth,
            "info": file_info,
            "findings": analysis_results,
            "telemetry": telemetry,
            "nested": []
        }

        if "artifacts" in analysis_results:
            for artifact in analysis_results["artifacts"]:
                artifact_path = artifact["path"]
                if os.path.exists(artifact_path):
                    nested_result = self.run(artifact_path, depth + 1)
                    if nested_result:
                        current_node["nested"].append({
                            "relation": "extracted_from_parent",
                            "artifact_name": artifact["name"],
                            "analysis": nested_result
                        })

        return current_node

    def calculate_risk_score(self, node):
        score = 0
        findings = node['findings']
        
        # Base on verdict
        if findings['verdict'] == 'Stego Detected': score += 50
        elif findings['verdict'] == 'Suspicious': score += 20
        
        # Base on details
        for d in findings['details']:
            if d['severity'] == 'danger': score += 15
            elif d['severity'] == 'warning': score += 5
            
        # Base on nesting depth (deeper hidden things are more suss)
        if node['depth'] > 0:
            score += 10
        
        # Add nested scores
        for nest in node['nested']:
            score += self.calculate_risk_score(nest['analysis'])
            
        return min(score, 100)

    def _get_analyzer(self, mime, file_path):
        if mime.startswith('image/'):
            return ImageAnalyzer(file_path)
        elif mime == 'application/pdf':
            return PDFAnalyzer(file_path)
        elif mime.startswith('audio/'):
            return AudioAnalyzer(file_path)
        elif mime == 'application/zip' or mime.startswith('application/vnd.openxmlformats-officedocument'):
            return ArchiveAnalyzer(file_path)
        elif mime in ['application/vnd.tcpdump.pcap', 'application/x-pcapng']:
            return NetworkAnalyzer(file_path)
        elif mime.startswith('text/') or mime == 'application/rtf' or 'wordprocessingml' in mime:
            return TextAnalyzer(file_path)
        else:
            return GenericAnalyzer(file_path)