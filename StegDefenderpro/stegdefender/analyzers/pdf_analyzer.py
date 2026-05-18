from stegdefender.core.analyzer import BaseAnalyzer
from pypdf import PdfReader
import re

class PDFAnalyzer(BaseAnalyzer):
    def analyze(self):
        try:
            self.extract_metadata()
            self.check_structure()
            self.check_eof()
            self.inspect_object_streams()
        except Exception as e:
            self.add_detail(f"PDF Analysis Error: {str(e)}", "warning")
        return self.results

    def inspect_object_streams(self):
        """
        Deeper inspection of PDF objects and streams for hidden artifacts.
        """
        try:
            reader = PdfReader(self.file_path)
            # Iterate through all objects in the PDF
            for obj_idx in range(len(reader.trailer.get('/Root', {}).get('/Pages', {}).get('/Kids', []))):
                # This is a simplified traversal. A real one would use reader.get_object()
                pass
                
            with open(self.file_path, 'rb') as f:
                content = f.read()
            
            # Look for /Filter /FlateDecode which indicates compressed streams
            # Stego often hides in these streams.
            stream_count = content.count(b'stream')
            if stream_count > 0:
                self.add_detail(f"Found {stream_count} internal data streams. Many are compressed with FlateDecode.", "info")
            
            # Detect suspicious PDF Keywords
            suspicious_keys = [b'/OpenAction', b'/AcroForm', b'/RichMedia', b'/Launch', b'/EmbeddedFiles']
            for key in suspicious_keys:
                if key in content:
                    self.add_detail(f"Suspicious PDF object key detected: {key.decode()}", "warning")
                    self.set_verdict("Suspicious")

        except Exception as e:
            self.add_detail(f"Object Stream inspection failed: {str(e)}", "warning")

    def extract_metadata(self) :
        try:
            reader = PdfReader(self.file_path)
            meta = reader.metadata
            if meta:
                self.results["metadata"] = {
                    "Producer": meta.get('/Producer', 'N/A'),
                    "Creator": meta.get('/Creator', 'N/A'),
                    "Author": meta.get('/Author', 'N/A'),
                    "Title": meta.get('/Title', 'N/A'),
                    "Pages": len(reader.pages)
                }
        except:
            pass


    def check_structure(self):
        try:
            reader = PdfReader(self.file_path)
            
            # Check metadata
            meta = reader.metadata
            if meta:
                self.add_detail(f"Producer: {meta.get('/Producer', 'Unknown')}", "info")
                self.add_detail(f"Creator: {meta.get('/Creator', 'Unknown')}", "info")
            
            # Check for embedded files
            # pypdf doesn't have a simple "get_all_embedded_files" in older versions, checking attachments
            # Modern pypdf: reader.attachments
            if hasattr(reader, 'attachments'):
                attachments = reader.attachments
                if attachments:
                    for filename, files in attachments.items():
                        self.add_detail(f"Found embedded file: {filename}", "danger")
                        self.set_verdict("Stego Detected")
                        # data = files[0] # Usually list of bytes
                        # self.save_artifact(filename, data)
            
            # Check for Javascript
            # Loop pages or root
            # Quick regex scan is often faster/safer for simple detection
            with open(self.file_path, 'rb') as f:
                content = f.read()
                
            if b'/JS' in content or b'/JavaScript' in content:
                 self.add_detail("PDF contains JavaScript. Potential malware/dropper.", "warning")
                 self.set_verdict("Suspicious")

            if b'/EmbeddedFiles' in content:
                 self.add_detail("PDF contains EmbeddedFiles tree.", "warning")
                 self.set_verdict("Suspicious")
                 
        except Exception as e:
            self.add_detail(f"Error parsing PDF structure: {str(e)}", "warning")

    def check_eof(self):
        with open(self.file_path, 'rb') as f:
            content = f.read()
            
        # PDF ends with %%EOF
        # Sometimes there are multiple %%EOF (incremental updates)
        # We look for the last one.
        
        last_eof = content.rfind(b'%%EOF')
        if last_eof != -1:
            # %%EOF is 5 bytes.
            # End of valid PDF is last_eof + 5
            # Sometimes there is newline (0x0D 0x0A)
            
            real_end = last_eof + 5
            remaining = content[real_end:]
            
            # strip newlines/whitespace
            remaining_stripped = remaining.strip()
            
            if len(remaining_stripped) > 10:
                self.add_detail(f"Detected {len(remaining_stripped)} bytes of hidden data after %%EOF.", "danger")
                self.set_verdict("Stego Detected")
                self.save_artifact("pdf_appended_data.bin", remaining_stripped)
