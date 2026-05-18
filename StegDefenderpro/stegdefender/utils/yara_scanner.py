# Forensic YARA-like rules for signature matching
# These are basic hex/string patterns used to flag malicious indicators in extracted data.

RULES = [
    {
        "id": "SHELLCODE_NOPS",
        "name": "Shellcode NOP Sled",
        "pattern": b"\x90\x90\x90\x90\x90\x90\x90\x90",
        "description": "Long sequence of NOP instructions, indicative of buffer overflow exploits.",
        "severity": "danger"
    },
    {
        "id": "SHELLCODE_CALL_POP",
        "name": "Shellcode GetPC (Call/Pop)",
        "pattern": b"\xe8\x00\x00\x00\x00\x58", # Call +5, Pop EAX
        "description": "GetPC code sequence used in position-independent shellcode.",
        "severity": "danger"
    },
    {
        "id": "POWERSHELL_CMD",
        "name": "PowerShell Command",
        "pattern": b"powershell",
        "description": "Explicit reference to PowerShell, potential dropper.",
        "severity": "danger"
    },
    {
        "id": "BASH_SHELL",
        "name": "Bash Shell Invocation",
        "pattern": b"/bin/bash",
        "description": "Reference to bash shell, potential unix payload.",
        "severity": "danger"
    },
    {
        "id": "CMD_SHELL",
        "name": "Windows Command Shell",
        "pattern": b"cmd.exe",
        "description": "Reference to cmd.exe, potential windows payload.",
        "severity": "danger"
    },
    {
        "id": "URL_HTTP",
        "name": "Embedded HTTP URL",
        "pattern": b"http://",
        "description": "Unencrypted HTTP URL, potential C2 or download link.",
        "severity": "warning"
    },
    {
        "id": "URL_HTTPS",
        "name": "Embedded HTTPS URL",
        "pattern": b"https://",
        "description": "HTTPS URL, potential C2 or download link.",
        "severity": "warning"
    },
    {
        "id": "IP_ADDR_LOCAL",
        "name": "Local IP Address",
        "pattern": b"127.0.0.1",
        "description": "Reference to localhost.",
        "severity": "info"
    },
    {
        "id": "PE_HEADER",
        "name": "Windows PE Header",
        "pattern": b"This program cannot be run in DOS mode",
        "description": "Standard Windows executable stub string.",
        "severity": "danger"
    },
    {
        "id": "ELF_HEADER",
        "name": "Linux ELF Header",
        "pattern": b"\x7fELF",
        "description": "Linux executable signature.",
        "severity": "danger"
    },
    {
        "id": "PHP_TAG",
        "name": "PHP Script Tag",
        "pattern": b"<?php",
        "description": "PHP opening tag, indicates web shell or script.",
        "severity": "danger"
    },
    {
        "id": "BASE64_PE",
        "name": "Base64 Encoded PE Header",
        "pattern": b"TVqQAAMAAAAEAAAA//8AALgAAAA", # "MZ" header in Base64
        "description": "Detected Base64 encoded Windows executable.",
        "severity": "danger"
    },
    {
        "id": "EICAR_TEST",
        "name": "EICAR Test File",
        "pattern": b"X5O!P%@AP[4\\PZX54(P^)\\7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        "description": "Standard antivirus test signature.",
        "severity": "danger"
    },
    # Steganography Tool Fingerprinting (New)
    {
        "id": "STEGHIDE_HDR",
        "name": "Steghide Signature",
        "pattern": b"\x00\x00\x00\x01\x00\x00\x00\x02", # Potential Steghide internal header snippet
        "description": "Likely signature of Steghide steganography tool.",
        "severity": "danger"
    },
    {
        "id": "OPENSTEGO_HDR",
        "name": "OpenStego Signature",
        "pattern": b"OPENSTEGO",
        "description": "Explicit OpenStego identifier found in data.",
        "severity": "danger"
    },
    {
        "id": "JSTEG_SIG",
        "name": "JSteg Header",
        "pattern": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01", # Standard but often modified by JSteg
        "description": "Potential JSteg modification detected.",
        "severity": "warning"
    },
    {
        "id": "OUTGUESS_SIG",
        "name": "OutGuess Pattern",
        "pattern": b"outguess",
        "description": "OutGuess steganography tool reference detected.",
        "severity": "danger"
    }
]

class YaraScanner:
    @staticmethod
    def scan(data):
        """
        Scans binary data against the ruleset.
        Returns a list of matched rules.
        """
        matches = []
        # Convert data to lower for case-insensitive string matching where appropriate
        # For strict binary patterns, we use original data.
        
        # Optimization: Don't scan huge files completely with python loops if unnecessary
        # But here we assume artifacts are reasonably sized. 
        
        for rule in RULES:
            # We treat the pattern as bytes.
            pat = rule["pattern"]
            if not pat: continue
            
            if pat in data:
                matches.append(rule)
            
            # Case insensitive check for text-based patterns (heuristic)
            elif len(pat) > 3 and pat.isalpha():
                if pat.lower() in data.lower():
                    matches.append(rule)

        return matches