from stegdefender.core.analyzer import BaseAnalyzer
import os
import re

class TextAnalyzer(BaseAnalyzer):
    def analyze(self):
        try:
            self.results["metadata"] = {
                "Type": "Text/Document",
                "Size": f"{os.path.getsize(self.file_path)} bytes"
            }
            
            with open(self.file_path, 'rb') as f:
                content = f.read()
                
            self.check_zero_width(content)
            self.check_base64(content)
            self.check_hex_strings(content)
            
        except Exception as e:
            self.add_detail(f"Text Analysis Error: {str(e)}", "warning")
            
        return self.results

    def check_zero_width(self, content):
        """
        Detects Zero-Width Characters (ZWC) used for hiding data in plain text.
        Common ZWCs:
        U+200B (Zero Width Space)
        U+200C (Zero Width Non-Joiner)
        U+200D (Zero Width Joiner)
        U+FEFF (Zero Width No-Break Space)
        """
        # UTF-8 encodings for ZWCs
        zwc_patterns = {
            b'\xe2\x80\x8b': "Zero Width Space (U+200B)",
            b'\xe2\x80\x8c': "Zero Width Non-Joiner (U+200C)",
            b'\xe2\x80\x8d': "Zero Width Joiner (U+200D)",
            b'\xef\xbb\xbf': "Zero Width No-Break Space (U+FEFF)"
        }
        
        found_zwcs = {}
        for pattern, name in zwc_patterns.items():
            count = content.count(pattern)
            if count > 0:
                found_zwcs[name] = count
                
        if found_zwcs:
            details = ", ".join([f"{name}: {count}" for name, count in found_zwcs.items()])
            self.add_detail(f"Detected Zero-Width Characters: {details}", "danger")
            self.set_verdict("Stego Detected")
            
            # Attempt to extract the "hidden" binary if it's a significant amount
            # Usually, ZWCs are used as binary 0/1 (e.g., U+200B = 0, U+200C = 1)
            # This is complex to auto-decode without knowing the scheme, but we flag it.
            self.add_detail("Possible 'Snow' or 'ZWC' steganography detected. Invisible data is likely embedded between visible characters.", "warning")

    def check_base64(self, content):
        """
        Scan for long base64-like strings which might be payloads.
        """
        # Regex for base64: at least 32 chars of [A-Za-z0-9+/=]
        b64_regex = b'[A-Za-z0-9+/]{32,}={0,2}'
        matches = re.findall(b64_regex, content)
        if matches:
            for match in matches:
                if len(match) > 64:
                    self.add_detail(f"Found suspicious long Base64 string ({len(match)} bytes).", "warning")
                    self.set_verdict("Suspicious")
                    # Save a sample if it's really long
                    if len(match) > 256:
                        self.save_artifact(f"extracted_b64_payload.txt", match)

    def check_hex_strings(self, content):
        """
        Scan for long hex-encoded strings.
        """
        hex_regex = b'[0-9a-fA-F]{64,}'
        matches = re.findall(hex_regex, content)
        if matches:
            self.add_detail(f"Found {len(matches)} suspicious hex-encoded strings.", "warning")
            self.set_verdict("Suspicious")
