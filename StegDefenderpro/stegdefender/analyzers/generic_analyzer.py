from stegdefender.core.analyzer import BaseAnalyzer
from stegdefender.utils.entropy import calculate_entropy
from stegdefender.core.crypto import CryptoManager
import re
import os

class GenericAnalyzer(BaseAnalyzer):
    def analyze(self):
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            self.results["metadata"] = {
                "Size": f"{len(data)} bytes",
                "Type": "Generic/Unknown"
            }
            
            entropy = calculate_entropy(data)
            self.add_detail(f"File Entropy: {entropy:.4f}", "info")
            
            if entropy > 7.9:
                 self.add_detail("High entropy. Possible encrypted or compressed content.", "warning")
                 self.set_verdict("Suspicious")
            
            # Simple strings extraction
            text_content = data.decode('utf-8', errors='ignore')
            
            # Look for common indicators like URLs, IPs, or flags
            self.check_urls(text_content)
            
            # CRITICAL: Check for encrypted hex tokens and try to decrypt them with wordlist
            self.try_decrypt_hex_tokens(text_content)
            
        except Exception as e:
            self.add_detail(f"Error in generic analysis: {str(e)}", "warning")
            
        return self.results

    def check_urls(self, text):
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        if urls:
            self.add_detail(f"Found {len(urls)} URLs inside file.", "warning")
            for url in urls[:3]: # Show first 3
                self.add_detail(f"URL: {url}", "warning")

    def try_decrypt_hex_tokens(self, text):
        # AES-GCM tokens from CryptoManager are hex strings.
        # Format: salt(16) + iv(12) + tag(16) + ciphertext
        # Min length is (16+12+16)*2 = 88 hex chars.
        hex_tokens = re.findall(r'[0-9a-fA-F]{88,}', text)
        
        if not hex_tokens:
            return

        # Load wordlist
        wordlist_path = os.path.join(os.path.dirname(__file__), "..", "utils", "wordlist.txt")
        passwords = []
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', encoding='latin-1') as f:
                passwords = [line.strip() for line in f]
        
        if not passwords:
            return

        for token in hex_tokens:
            # Try AES first (it has built-in integrity check)
            for pwd in passwords:
                try:
                    plaintext = CryptoManager.decrypt_aes(token, pwd)
                    if plaintext:
                        msg = plaintext.decode('utf-8', errors='ignore')
                        # Check if it looks like reasonable text
                        if any(c.isalpha() for c in msg):
                            self.add_detail(f"SUCCESSFULLY DECRYPTED (AES): {msg}", "danger")
                            self.add_detail(f"Decryption Password: {pwd}", "info")
                            self.set_verdict("Stego Detected")
                            self.save_artifact("decrypted_message.txt", plaintext)
                            return # Stop on first success
                except:
                    pass
            
            # Try ChaCha20 (heuristic - check for high printable ratio)
            for pwd in passwords:
                try:
                    plaintext = CryptoManager.decrypt_chacha(token, pwd)
                    if plaintext:
                        msg = plaintext.decode('utf-8', errors='ignore')
                        # Heuristic: at least 70% printable and has some letters
                        printable_ratio = sum(1 for c in msg if c.isprintable()) / len(msg)
                        if printable_ratio > 0.8 and any(c.isalpha() for c in msg):
                            self.add_detail(f"SUCCESSFULLY DECRYPTED (ChaCha): {msg}", "danger")
                            self.add_detail(f"Decryption Password: {pwd}", "info")
                            self.set_verdict("Stego Detected")
                            self.save_artifact("decrypted_message.txt", plaintext)
                            return
                except:
                    pass
