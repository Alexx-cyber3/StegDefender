import os
import subprocess
import shutil

class StegoExtractor:
    @staticmethod
    def extract(file_path, password=None):
        """
        Attempts to extract hidden data from a file.
        Prioritizes Steghide if applicable, then falls back to EOF extraction.
        Returns the extracted bytes or None.
        """
        # 1. Try Steghide (if it's a supported format and tool exists)
        # Steghide supports JPEG, BMP, WAV, AU
        ext = os.path.splitext(file_path)[1].lower()
        if ext in ['.jpg', '.jpeg', '.bmp', '.wav', '.au'] and shutil.which("steghide"):
            try:
                # Steghide requires a password (even if empty)
                pwd = password if password else ""
                
                # Output to a temp file
                output_path = file_path + ".extracted"
                if os.path.exists(output_path):
                    os.remove(output_path)

                cmd = ["steghide", "extract", "-sf", file_path, "-p", pwd, "-xf", output_path, "-f"]
                
                # Run silently
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=5
                )
                
                if result.returncode == 0 and os.path.exists(output_path):
                    with open(output_path, "rb") as f:
                        data = f.read()
                    os.remove(output_path)
                    return data
            except Exception as e:
                print(f"Steghide extraction failed: {e}")

        # 2. Try EOF Extraction (Appended Data)
        # This handles "Polyglot" or simple appended archives/data
        return StegoExtractor._extract_eof(file_path)

    @staticmethod
    def _extract_eof(file_path):
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # JPEG (FF D9)
            if content.startswith(b'\xff\xd8'):
                end = content.rfind(b'\xff\xd9')
                if end != -1 and end + 2 < len(content):
                    return content[end+2:]
            
            # PNG (IEND)
            elif content.startswith(b'\x89PNG'):
                end = content.find(b'IEND')
                if end != -1:
                    # IEND chunk is 4(len) + 4(type) + 0(data) + 4(crc) = 12 bytes. 
                    # Structure: Length(4) + 'IEND' + CRC(4).
                    # 'IEND' index points to 'I', so we need +4(IEND) +4(CRC) = +8
                    real_end = end + 8
                    if real_end < len(content):
                        return content[real_end:]
            
            # GIF (0x3B)
            elif content.startswith(b'GIF'):
                end = content.rfind(b'\x3b')
                if end != -1 and end < len(content) - 1:
                    return content[end+1:]
            
        except Exception:
            pass
        
        return None
