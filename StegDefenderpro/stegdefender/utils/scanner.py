# Common file signatures (Magic Bytes)
SIGNATURES = {
    b'\x50\x4b\x03\x04': 'ZIP Archive / Office Doc',
    b'\x25\x50\x44\x46': 'PDF Document',
    b'\x89\x50\x4e\x47': 'PNG Image',
    b'\xff\xd8\xff': 'JPEG Image',
    b'MZ': 'Windows Executable (EXE/DLL)',
    b'\x7fELF': 'Linux Executable (ELF)',
    b'Rar!': 'RAR Archive',
    b'\x1f\x8b\x08': 'GZIP Archive',
    b'ID3': 'MP3 Audio Tag',
    b'7z\xbc\xaf\x27\x1c': '7-Zip Archive',
    b'<!DOCTYPE html': 'HTML Document',
    b'<?php': 'PHP Script',
}

def scan_for_signatures(data):
    """
    Scans binary data for known file signatures (Binwalk-style).
    Returns a list of found signatures with their offsets.
    """
    matches = []
    
    for signature, description in SIGNATURES.items():
        offset = 0
        while True:
            index = data.find(signature, offset)
            if index == -1:
                break
            
            # Ignore signature if it's at the very beginning (0), as that's just the file itself.
            # We are looking for *embedded* files.
            if index > 0:
                matches.append({
                    "offset": index,
                    "description": description,
                    "signature": signature.hex()
                })
            
            offset = index + 1
            
    # Sort by offset
    matches.sort(key=lambda x: x["offset"])
    return matches
