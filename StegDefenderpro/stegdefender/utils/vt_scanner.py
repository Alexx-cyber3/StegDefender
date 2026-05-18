import hashlib
import json
import logging

class VTScanner:
    """
    Mock VirusTotal Scanner for forensic analysis.
    In a real-world scenario, this would use an API key to query 
    VirusTotal for file hashes of extracted artifacts.
    """
    
    # Mock database of "malicious" hashes for demo purposes
    MOCK_DATABASE = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
            "name": "Empty File",
            "malicious": 0,
            "total": 70
        },
        "44d88612fea8a8f36de82e1278abb02f": { # Mock hash for a known web shell
            "name": "Backdoor.PHP.WebShell.gen",
            "malicious": 58,
            "total": 72,
            "link": "https://www.virustotal.com/gui/file/sample_hash"
        }
    }

    @staticmethod
    def scan_hash(file_data):
        """
        Calculates SHA256 hash and 'queries' mock VirusTotal.
        """
        sha256 = hashlib.sha256(file_data).hexdigest()
        
        # Check mock DB
        if sha256 in VTScanner.MOCK_DATABASE:
            return {
                "hash": sha256,
                "found": True,
                "data": VTScanner.MOCK_DATABASE[sha256]
            }
        
        # Random simulation for other hashes
        return {
            "hash": sha256,
            "found": False,
            "message": "No match found in VirusTotal database (Simulated)."
        }

    @staticmethod
    def get_analysis_summary(file_data):
        """
        Convenience method for the analyzer to get a string summary.
        """
        res = VTScanner.scan_hash(file_data)
        if res["found"]:
            d = res["data"]
            return f"VirusTotal Match! {d['name']} (Score: {d['malicious']}/{d['total']})"
        return f"SHA256: {res['hash']} (Clean or unknown)"
