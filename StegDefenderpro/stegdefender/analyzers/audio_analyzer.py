from stegdefender.core.analyzer import BaseAnalyzer
import struct
import os

class AudioAnalyzer(BaseAnalyzer):
    def analyze(self):
        try:
            self.results["metadata"] = {
                "Type": "Audio",
                "Size": f"{os.path.getsize(self.file_path)} bytes"
            }
            with open(self.file_path, 'rb') as f:
                header = f.read(4)
                
            if header == b'RIFF':
                self.analyze_wav()
            elif header.startswith(b'ID3') or header.startswith(b'\xff\xfb') or header.startswith(b'\xff\xf3') or header.startswith(b'\xff\xf2'):
                self.analyze_mp3()
            else:
                 self.add_detail("Unknown audio format or raw stream.", "info")
                 
        except Exception as e:
            self.add_detail(f"Audio Analysis Error: {str(e)}", "warning")
            
        return self.results

    def analyze_wav(self):
        # WAV Structure: RIFF [size] WAVE [chunks...]
        # We walk the chunks.
        try:
            with open(self.file_path, 'rb') as f:
                f.seek(0, 2)
                file_size = f.tell()
                f.seek(0)
                
                # RIFF header
                chunk_id = f.read(4) # RIFF
                if chunk_id != b'RIFF':
                    return
                    
                chunk_size = struct.unpack('<I', f.read(4))[0] # Size of rest of file
                format_ = f.read(4) # WAVE
                
                if format_ != b'WAVE':
                    return

                # Expected file size is chunk_size + 8 (RIFF + Size bytes)
                expected_size = chunk_size + 8
                
                if file_size > expected_size + 8: # tolerance
                    diff = file_size - expected_size
                    self.add_detail(f"File size ({file_size}) larger than RIFF declared size ({expected_size}). Extra {diff} bytes.", "danger")
                    self.set_verdict("Stego Detected")
                    
                    f.seek(expected_size)
                    extra_data = f.read()
                    self.save_artifact("wav_appended_data.bin", extra_data)
                
                # Scan chunks for unknown ones
                # Reset to after WAVE
                f.seek(12)
                while f.tell() < expected_size:
                    try:
                        sub_chunk_id = f.read(4)
                        if not sub_chunk_id: break
                        sub_chunk_size = struct.unpack('<I', f.read(4))[0]
                        
                        # Pad byte if size is odd
                        padding = sub_chunk_size % 2
                        
                        self.add_detail(f"Chunk: {sub_chunk_id.decode('utf-8', 'ignore')} ({sub_chunk_size} bytes)", "info")
                        
                        # Check for unusual chunks
                        # Standard: fmt , data, fact, cue, plst, list, labl, note, ltxt, sampler, inst, bext, iXML
                        # Suspicious: anything else often used for hiding
                        
                        safe_chunks = [b'fmt ', b'data', b'fact', b'LIST', b'id3 ', b'bext', b'JUNK']
                        if sub_chunk_id not in safe_chunks:
                             # Warning only, as many legitimate custom chunks exist
                             # But good to note
                             pass
                        
                        # Skip data
                        f.seek(sub_chunk_size + padding, 1)
                    except struct.error:
                        break
                        
        except Exception as e:
             self.add_detail(f"WAV Parsing Error: {str(e)}", "warning")

    def analyze_mp3(self):
        # MP3 simple check: ID3 tags usually at start. 
        # Check for data appended after frames is hard without full decoding.
        # We can check for concatenations (multiple ID3 tags).
        
        with open(self.file_path, 'rb') as f:
            content = f.read()
            
        id3_count = content.count(b'ID3')
        if id3_count > 1:
            self.add_detail(f"Found {id3_count} ID3 tags. Possible file concatenation/hiding.", "warning")
            self.set_verdict("Suspicious")
