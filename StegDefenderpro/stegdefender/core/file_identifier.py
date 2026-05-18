import filetype
import os
import mimetypes

class FileIdentifier:
    @staticmethod
    def identify(file_path):
        """
        Identifies the file type using magic numbers.
        Returns a dictionary with 'kind', 'mime', and 'extension'.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Manual Check for PCAP/PCAPNG (Network Captures)
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                # PCAP (Little Endian & Big Endian) and PCAPNG
                if header in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d']:
                     return {"type": "pcap", "mime": "application/vnd.tcpdump.pcap", "extension": "pcap"}
                if header == b'\x0a\x0d\x0d\x0a':
                     return {"type": "pcapng", "mime": "application/x-pcapng", "extension": "pcapng"}
        except:
            pass

        kind = filetype.guess(file_path)
        
        if kind is None:
            # Fallback to extension if magic bytes fail
            mime, _ = mimetypes.guess_type(file_path)
            ext = os.path.splitext(file_path)[1].lstrip('.').lower()
            
            if mime:
                return {
                    "type": ext if ext else "unknown",
                    "mime": mime,
                    "extension": ext if ext else "bin"
                }
            
            return {
                "type": "unknown",
                "mime": "application/octet-stream",
                "extension": "bin"
            }
        
        return {
            "type": kind.extension, # generic type label
            "mime": kind.mime,
            "extension": kind.extension
        }
