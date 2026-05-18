import subprocess
import os
import platform
import sys

class SteghideWrapper:
    @staticmethod
    def get_steghide_path():
        """
        Locates the steghide binary relative to the project root.
        """
        # Determine the project root (where bin folder lives)
        # Assuming this file is at stegdefender/utils/steghide_wrapper.py
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        
        system = platform.system().lower()
        if system == "windows":
            bin_path = os.path.join(project_root, "bin", "win", "steghide.exe")
        else:
            bin_path = os.path.join(project_root, "bin", "linux", "steghide")
            
        return bin_path if os.path.exists(bin_path) else None

    @staticmethod
    def is_available():
        return SteghideWrapper.get_steghide_path() is not None

    @staticmethod
    def get_info(file_path, password=""):
        steghide_bin = SteghideWrapper.get_steghide_path()
        if not steghide_bin:
            return False, False, "Steghide binary not found in /bin folder"

        try:
            cmd = [steghide_bin, "info", file_path, "-p", password]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            output = result.stdout + result.stderr
            
            if "does not appear to be a steghide file" in output:
                return False, False, None
            
            if "format: " in output:
                return True, False, output
            
            if "could not extract any data with that passphrase" in output or "bad passphrase" in output:
                return True, True, "Encrypted Steghide container detected"
                
            return False, False, "Unknown output"
            
        except Exception as e:
            return False, False, f"Error: {str(e)}"

    @staticmethod
    def extract(file_path, password="", output_path=None):
        steghide_bin = SteghideWrapper.get_steghide_path()
        if not steghide_bin:
            return None, "Steghide binary not found in /bin folder"

        import tempfile
        if output_path is None:
            temp_fd, output_path = tempfile.mkstemp()
            os.close(temp_fd)
            cleanup = True
        else:
            cleanup = False

        try:
            cmd = [steghide_bin, "extract", "-sf", file_path, "-p", password, "-xf", output_path, "-f"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                with open(output_path, "rb") as f:
                    data = f.read()
                if cleanup:
                    os.remove(output_path)
                return data, "Success"
            else:
                if cleanup and os.path.exists(output_path):
                    os.remove(output_path)
                return None, result.stderr or "Extraction failed"
                
        except Exception as e:
            if cleanup and os.path.exists(output_path):
                os.remove(output_path)
            return None, str(e)
