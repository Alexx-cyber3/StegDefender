from stegdefender.core.analyzer import BaseAnalyzer
import zipfile
import os

class ArchiveAnalyzer(BaseAnalyzer):
    """
    Handles ZIP and Office formats (DOCX, XLSX, PPTX) which are essentially ZIPs.
    """
    def analyze(self):
        try:
            self.check_zip_structure()
            self.check_eof()
        except Exception as e:
            self.add_detail(f"Archive Analysis Error: {str(e)}", "warning")
        return self.results

    def check_zip_structure(self):
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                self.results["metadata"] = {
                    "File Count": len(file_list),
                    "Type": "ZIP Archive"
                }
                self.add_detail(f"Archive contains {len(file_list)} internal files.", "info")
                
                # Check for suspicious file names or types inside
                suspicious_exts = ['.exe', '.bat', '.sh', '.py', '.bin']
                for name in file_list:
                    ext = os.path.splitext(name)[1].lower()
                    if ext in suspicious_exts:
                        self.add_detail(f"Suspicious file found inside archive: {name}", "danger")
                        self.set_verdict("Stego Detected")
                    
                    # Check for hidden files (starting with dot or in unusual paths)
                    if name.startswith('.') or '__MACOSX' in name:
                        self.add_detail(f"Hidden or system metadata file found: {name}", "warning")
                        self.set_verdict("Suspicious")

        except zipfile.BadZipFile:
            self.add_detail("File is not a valid ZIP/Office archive despite extension.", "danger")
            self.set_verdict("Suspicious")

    def check_eof(self):
        """
        ZIP files end with the 'End of Central Directory Record'.
        """
        with open(self.file_path, 'rb') as f:
            content = f.read()
            
        # The EOCD marker is \x50\x4b\x05\x06
        eocd_marker = b'\x50\x4b\x05\x06'
        last_eocd = content.rfind(eocd_marker)
        
        if last_eocd != -1:
            # The EOCD record is at least 22 bytes long.
            # But it can have a comment at the end (up to 65535 bytes).
            # The length of the comment is stored in the last 2 bytes of the 22-byte record.
            
            if len(content) > last_eocd + 22:
                import struct
                comment_len = struct.unpack('<H', content[last_eocd+20:last_eocd+22])[0]
                real_end = last_eocd + 22 + comment_len
                
                if len(content) > real_end:
                    extra_bytes = content[real_end:]
                    if len(extra_bytes) > 5:
                        self.add_detail(f"Detected {len(extra_bytes)} bytes of hidden data after ZIP EOCD.", "danger")
                        self.set_verdict("Stego Detected")
                        self.save_artifact("zip_appended_data.bin", extra_bytes)
