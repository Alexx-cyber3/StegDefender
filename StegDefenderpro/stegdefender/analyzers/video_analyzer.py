import os
import struct
from stegdefender.core.analyzer import BaseAnalyzer
from stegdefender.utils.entropy import calculate_entropy
from stegdefender.utils.evm_processor import EVMProcessor

class VideoAnalyzer(BaseAnalyzer):
    """
    Analyzes video files (MP4, AVI, etc.) for steganography.
    Focuses on:
    - Appended data (EOF)
    - Unusual MP4 boxes (atoms)
    - Metadata anomalies
    - Eulerian Video Magnification (EVM) for hidden pulse detection
    """
    def analyze(self):
        self.results["metadata"] = {
            "Type": "Video",
            "Size": f"{os.path.getsize(self.file_path)} bytes"
        }
        
        # 1. Run EVM X-Ray analysis first as it's the 'futuristic' part
        self.run_evm_analysis()
        
        try:
            with open(self.file_path, 'rb') as f:
                header = f.read(12)
            
            # Check for MP4 (ftyp box usually at start)
            if b'ftyp' in header:
                self.analyze_mp4()
            else:
                self.add_detail("Generic video format detection. Checking for EOF data.", "info")
                self.check_eof_generic()
                
        except Exception as e:
            self.add_detail(f"Video Analysis Error: {str(e)}", "warning")
            
        return self.results

    def run_evm_analysis(self):
        """
        Executes EVM to detect rhythmic steganographic pulsing.
        """
        self.add_detail("Executing Eulerian Video Magnification (EVM) X-Ray...", "info")
        try:
            output_name = f"evm_xray_{os.path.basename(self.file_path)}.mp4"
            output_path = os.path.join(self.extraction_dir, output_name)
            
            if not os.path.exists(self.extraction_dir):
                os.makedirs(self.extraction_dir)

            heatmap_path = EVMProcessor.amplify_video(self.file_path, output_path)
            
            if heatmap_path:
                self.add_detail("EVM Analysis Complete. 'X-Ray' video generated.", "success")
                
                # Save the magnified video as an artifact
                with open(output_path, 'rb') as f:
                    self.save_artifact(output_name, f.read())
                
                # Save the heatmap as a confirmed stego artifact if it shows high variance
                with open(heatmap_path, 'rb') as f:
                    self.save_artifact(os.path.basename(heatmap_path), f.read(), is_stego=False)
                    # Note: We don't mark is_stego=True yet as it needs human verification, 
                    # but it will appear in artifacts.
            else:
                self.add_detail("EVM Analysis skipped (insufficient frames).", "info")
                
        except Exception as e:
            self.add_detail(f"EVM Processing failed: {str(e)}", "warning")

    def analyze_mp4(self):
        """
        Parses MP4 boxes and checks for anomalies.
        """
        try:
            file_size = os.path.getsize(self.file_path)
            with open(self.file_path, 'rb') as f:
                offset = 0
                moov_found = False
                mdat_found = False
                
                while offset < file_size:
                    f.seek(offset)
                    data = f.read(8)
                    if len(data) < 8:
                        break
                    
                    size, box_type = struct.unpack('>I4s', data)
                    if size == 1: # 64-bit size
                        size_data = f.read(8)
                        if len(size_data) < 8: break
                        size = struct.unpack('>Q', size_data)[0]
                    elif size == 0: # Extends to EOF
                        size = file_size - offset

                    if size < 8 and size != 0:
                        # Corrupted box or end of stream
                        break

                    type_str = box_type.decode('ascii', errors='ignore')
                    
                    # Detect unusual boxes
                    if type_str == 'free' or type_str == 'skip':
                        box_data = f.read(min(size - 8, 1024))
                        entropy = calculate_entropy(box_data)
                        if entropy > 7.0 and len(box_data) > 64:
                            self.add_detail(f"High-entropy data in '{type_str}' box (size={size}). Possible hidden payload.", "danger")
                            self.set_verdict("Stego Detected")
                            self.save_artifact(f"mp4_{type_str}_data.bin", box_data, is_stego=True)
                    
                    if type_str == 'moov': moov_found = True
                    if type_str == 'mdat': mdat_found = True

                    # Advance to next box
                    offset += size
                    if size == 0: break # Safety

                # Check for data after last declared box
                if offset < file_size:
                    diff = file_size - offset
                    if diff > 10:
                        self.add_detail(f"Detected {diff} bytes of data after last MP4 box. Possible EOF stego.", "danger")
                        self.set_verdict("Stego Detected")
                        with open(self.file_path, 'rb') as f2:
                            f2.seek(offset)
                            extra_data = f2.read()
                            self.save_artifact("mp4_eof_data.bin", extra_data, is_stego=True)

        except Exception as e:
            self.add_detail(f"MP4 Parsing Error: {str(e)}", "warning")

    def check_eof_generic(self):
        """
        Simple entropy-based EOF check for non-MP4 videos.
        """
        try:
            file_size = os.path.getsize(self.file_path)
            # Read last 10KB
            read_size = min(file_size, 10240)
            with open(self.file_path, 'rb') as f:
                f.seek(-read_size, 2)
                tail = f.read()
                
            entropy = calculate_entropy(tail)
            if entropy > 7.8:
                self.add_detail(f"Very high entropy ({entropy:.2f}) at the end of the video file. Possible encrypted payload.", "warning")
                self.set_verdict("Suspicious")
        except:
            pass
