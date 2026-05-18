from stegdefender.core.analyzer import BaseAnalyzer
from stegdefender.utils.entropy import calculate_entropy
from stegdefender.utils.steghide_wrapper import SteghideWrapper
from PIL import Image
import os

class ImageAnalyzer(BaseAnalyzer):
    def analyze(self):
        self.extract_metadata()
        self.check_eof_data()
        self.check_visual_noise()
        self.check_steghide()
        return self.results

    def extract_metadata(self):
        try:
            with Image.open(self.file_path) as img:
                self.results["metadata"] = {
                    "Format": img.format,
                    "Mode": img.mode,
                    "Size": f"{img.width}x{img.height}",
                    "Format Info": img.format_description
                }
                
                # Basic EXIF
                if hasattr(img, '_getexif') and img._getexif():
                    exif = img._getexif()
                    if exif:
                        # Map common tags if needed, or just count them for now to avoid huge dumps
                        for tag, val in exif.items():
                            if tag == 305: self.results["metadata"]["Software"] = str(val)
                            if tag == 306: self.results["metadata"]["DateTime"] = str(val)
                            if tag == 271: self.results["metadata"]["Make"] = str(val)
                            if tag == 272: self.results["metadata"]["Model"] = str(val)
        except Exception as e:
             self.add_detail(f"Metadata extraction failed: {str(e)}", "warning")

    def check_eof_data(self):
        """
        Check for data appended after the valid image end.
        """
        try:
            with Image.open(self.file_path) as img:
                img_format = img.format
                
            with open(self.file_path, 'rb') as f:
                content = f.read()

            if img_format == 'JPEG':
                # Find last FFD9 (EOI)
                eoi_index = content.rfind(b'\xff\xd9')
                if eoi_index != -1 and eoi_index + 2 < len(content):
                    extra_bytes = content[eoi_index+2:]
                    if len(extra_bytes) > 10: # Tolerate small noise
                        self.add_detail(f"Detected {len(extra_bytes)} bytes of data after EOF (0xFFD9)", "danger")
                        self.set_verdict("Stego Detected")
                        self.save_artifact("extracted_eof_data.bin", extra_bytes)
            
            elif img_format == 'PNG':
                # Find IEND chunk
                iend_index = content.find(b'IEND')
                if iend_index != -1:
                    real_end = iend_index + 8
                    if real_end < len(content):
                         extra_bytes = content[real_end:]
                         if len(extra_bytes) > 10:
                            self.add_detail(f"Detected {len(extra_bytes)} bytes of data after PNG IEND chunk", "danger")
                            self.set_verdict("Stego Detected")
                            self.save_artifact("extracted_png_eof.bin", extra_bytes)

            elif img_format == 'GIF':
                # GIF ends with 0x3B
                trailer_index = content.rfind(b'\x3b')
                if trailer_index != -1 and trailer_index < len(content) - 1:
                    extra_bytes = content[trailer_index+1:]
                    if len(extra_bytes) > 5:
                        self.add_detail(f"Detected {len(extra_bytes)} bytes of data after GIF trailer (0x3B)", "danger")
                        self.set_verdict("Stego Detected")
                        self.save_artifact("extracted_gif_eof.bin", extra_bytes)

        except Exception as e:
            self.add_detail(f"Error analyzing image structure: {str(e)}", "warning")

    def check_visual_noise(self):
        """
        Check for high entropy which might indicate LSB steganography.
        """
        try:
            # Check LSB Entropy
            with Image.open(self.file_path) as img:
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Analyze a sample of pixels (e.g., center crop) to save time on large images
                width, height = img.size
                if width > 1000 or height > 1000:
                    img = img.resize((500, 500)) # Downscale for entropy check (approximation)
                
                pixels = list(img.getdata())
                lsbs = []
                for p in pixels:
                    lsbs.append(p[0] & 1)
                    lsbs.append(p[1] & 1)
                    lsbs.append(p[2] & 1)
                
                # Convert LSB bits to bytes for entropy calc
                lsb_bytes = bytearray()
                for i in range(0, len(lsbs), 8):
                    byte_val = 0
                    for j in range(8):
                        if i + j < len(lsbs):
                            byte_val |= (lsbs[i+j] << j)
                    lsb_bytes.append(byte_val)
                    
                lsb_entropy = calculate_entropy(lsb_bytes)
                self.add_detail(f"LSB Entropy: {lsb_entropy:.4f}", "info")
                
                # LSB Entropy close to 1.0 (per bit) or 8.0 (per byte) means random noise (encryption/compression)
                if lsb_entropy > 7.8: 
                    self.add_detail("LSB plane has max entropy (>7.8). High probability of LSB Steganography.", "danger")
                    self.set_verdict("Stego Detected")
                elif lsb_entropy > 7.5:
                     self.add_detail("LSB plane has high entropy (>7.5). Suspicious.", "warning")
                     self.set_verdict("Suspicious")

        except Exception as e:
            self.add_detail(f"Error analyzing LSB: {str(e)}", "warning")

    def check_steghide(self):
        """
        Use Steghide tool to check for hidden data if available.
        """
        if not SteghideWrapper.is_available():
            self.add_detail("Steghide tool not found. Skipping deep bitstream analysis.", "info")
            return

        is_stego, encrypted, info = SteghideWrapper.get_info(self.file_path)
        if is_stego:
            if encrypted:
                self.add_detail("Steghide container detected (Encrypted).", "danger")
                self.set_verdict("Stego Detected")
            else:
                self.add_detail("Steghide container detected (No passphrase or default used).", "danger")
                self.set_verdict("Stego Detected")
                # Try to extract it immediately if not encrypted (empty pwd)
                data, msg = SteghideWrapper.extract(self.file_path, password="")
                if data:
                    self.save_artifact("steghide_extracted.bin", data, is_stego=True)
