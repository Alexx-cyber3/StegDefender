import zipfile
import os
import subprocess
import shutil
import filetype
from pypdf import PdfReader

class Cracker:
    def __init__(self, wordlist_path=None):
        if wordlist_path is None:
            # Default to the one we just created
            self.wordlist_path = os.path.join(os.path.dirname(__file__), "..", "utils", "wordlist.txt")
        else:
            self.wordlist_path = wordlist_path

    def crack(self, file_path, mime_type, custom_passwords=None):
        """
        Attempts to crack the file based on mime type.
        Returns the password if found, or None.
        """
        passwords = []
        if custom_passwords:
            passwords = custom_passwords
        elif os.path.exists(self.wordlist_path):
            with open(self.wordlist_path, 'r', encoding='latin-1') as f:
                passwords = [line.strip() for line in f]
        else:
            return {"status": "error", "message": "Wordlist not found."}

        # Check if it's a valid ZIP (polyglot or regular)
        # zipfile.is_zipfile checks for the End of Central Directory signature, 
        # so it works for images with appended ZIPs.
        if zipfile.is_zipfile(file_path):
            zip_result = self._crack_zip(file_path, passwords)
            if zip_result["status"] == "success":
                return zip_result
            # If failed, continue to other checks (e.g. might be a coincidence or steghide)
        
        if mime_type == 'application/zip':
            # Already checked above, but if it failed there, it failed here.
            return {"status": "failed", "message": "Password not found in dictionary (ZIP)."}
        
        elif mime_type == 'application/pdf':
            return self._crack_pdf(file_path, passwords)
            
        elif mime_type in ['image/jpeg', 'image/jpg', 'image/bmp', 'audio/wav', 'audio/x-wav']:
            return self._crack_steghide(file_path, passwords)
            
        else:
            return {"status": "skipped", "message": f"Cracking not supported for {mime_type}"}

    def _crack_zip(self, file_path, passwords):
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                # Get list of files
                files = zf.namelist()
                if not files:
                     return {"status": "failed", "message": "Empty ZIP archive."}
                     
                for pwd in passwords:
                    try:
                        # Try to open first file with password
                        zf.read(files[0], pwd=pwd.encode('utf-8'))
                        return {"status": "success", "password": pwd}
                    except (RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
                        # RuntimeError is raised for bad password in zipfile
                        continue
        except Exception as e:
            return {"status": "error", "message": str(e)}
        
        return {"status": "failed", "message": "Password not found in dictionary."}

    def _crack_pdf(self, file_path, passwords):
        try:
            reader = PdfReader(file_path)
            if not reader.is_encrypted:
                return {"status": "info", "message": "PDF is not encrypted."}

            for pwd in passwords:
                # pypdf decrypt returns 1 or 2 on success, 0 on fail
                if reader.decrypt(pwd) > 0:
                    return {"status": "success", "password": pwd}
        except Exception as e:
             return {"status": "error", "message": str(e)}

        return {"status": "failed", "message": "Password not found in dictionary."}

    def _crack_steghide(self, file_path, passwords):
        from stegdefender.utils.steghide_wrapper import SteghideWrapper
        
        if not SteghideWrapper.is_available():
            return {"status": "error", "message": "Steghide tool not found."}

        # First check if it's even a steghide file to avoid wasting time
        is_stego, encrypted, info = SteghideWrapper.get_info(file_path)
        if not is_stego:
            return {"status": "failed", "message": "Not a Steghide file."}

        for pwd in passwords:
            # We use extract with a small timeout or info to check password
            # get_info returns encrypted=False if the password is correct!
            is_stego, encrypted, info = SteghideWrapper.get_info(file_path, password=pwd)
            if is_stego and not encrypted:
                return {"status": "success", "password": pwd}

        return {"status": "failed", "message": "Password not found in dictionary."}

