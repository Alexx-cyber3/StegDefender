from abc import ABC, abstractmethod
import os
import time
from stegdefender.core.file_identifier import FileIdentifier

class BaseAnalyzer(ABC):
    def __init__(self, file_path):
        self.file_path = file_path
        self.results = {
            "verdict": "Clean",
            "details": [],
            "artifacts": [],
            "metadata": {}
        }
        # Ensure extraction_dir is absolute and points to the project root's extracted_data
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.extraction_dir = os.path.join(base_dir, "stegdefender", "extracted_data", str(int(time.time())))

    @abstractmethod
    def analyze(self):
        """
        Perform the analysis and populate self.results.
        """
        pass

    def add_detail(self, message, severity="info"):
        """
        Add a detail to the results.
        Severity: info, warning, danger
        """
        self.results["details"].append({
            "message": message,
            "severity": severity
        })

    def set_verdict(self, verdict):
        """
        Set the final verdict: Clean, Suspicious, Stego Detected
        """
        # Priority: Stego Detected > Suspicious > Clean
        current = self.results["verdict"]
        if current == "Stego Detected":
            return # Already max severity
        
        if verdict == "Stego Detected":
            self.results["verdict"] = verdict
        elif verdict == "Suspicious" and current == "Clean":
            self.results["verdict"] = verdict

    def save_artifact(self, name, data):
        """
        Save extracted data to the extraction directory.
        """
        if not os.path.exists(self.extraction_dir):
            os.makedirs(self.extraction_dir)
            
        # Try to identify what we extracted
        type_info = "unknown"
        try:
            # We can use our own FileIdentifier logic if we write it to a temp file, 
            # or just quick magic check on bytes
            import filetype
            kind = filetype.guess(data)
            if kind:
                type_info = kind.extension
                if not name.endswith(f".{kind.extension}"):
                    name = f"{name}.{kind.extension}"
        except:
            pass

        path = os.path.join(self.extraction_dir, name)
        with open(path, 'wb') as f:
            f.write(data)
            
        self.results["artifacts"].append({
            "name": name,
            "path": path,
            "type": type_info,
            "size": len(data)
        })
        
        self.add_detail(f"Extracted artifact: {name} ({type_info})", "warning")