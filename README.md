# StegDefender
 Project Overview: It is a Recursive Forensic Engine. Unlike simple tools that check a file once,       StegDefenderPro extracts hidden artifacts and recursively analyzes them. If a ZIP is hidden in an image, it           extracts the ZIP and then analyzes the files inside that ZIP for further steganography.    

  1. Core Architecture
  The tool follows a modular "Engine-Analyzer" pattern:
   * Forensic Engine (core/engine.py): The central orchestrator. It identifies the file type (via magic bytes), selects the appropriate analyzer, and manages the       
     recursion process.
   * Recursive Workflow: When an analyzer extracts a hidden file (artifact), the engine automatically triggers a new analysis pass on that artifact, building a
     "Forensic Tree" of all discovered layers.
   * Risk Scoring: It calculates a global "Risk Score" (0-100) based on the severity of findings (e.g., confirmed steganography, suspicious entropy, or malware
     signatures).

  2. Specialized Analyzers
  The tool includes several domain-specific modules:
   * Image Analyzer: Detects data appended after the standard file terminator (EOF) and performs LSB (Least Significant Bit) Entropy Analysis. High entropy in the LSB  
     plane (>7.8) is flagged as a strong indicator of encrypted hidden data.
   * Network Analyzer: Uses Scapy to process PCAP captures. It detects:
       * ICMP/DNS Covert Channels: High-entropy payloads in pings or unusually long/random DNS subdomains.
       * Protocol Carving: Reassembles TCP/HTTP streams to extract files being transferred.
       * Timing Analysis: Detects "beacons" (regularly timed packets) indicative of automated C2 (Command & Control) traffic.
  3. Advanced Forensic Features
   * Entropy Mapping: Generates a visual map of a file's "randomness." Since encrypted or compressed data has high entropy, spikes in the map reveal the exact location 
     of hidden payloads.
   * Automated Cracking (core/cracker.py): A built-in brute-force engine that uses a wordlist to attempt to unlock:
       * Password-protected ZIPs and PDFs.
       * Files protected by Steghide (via system integration).
   * Signature Matching (YARA): Uses hex and string patterns to detect malware "droppers," shellcode (e.g., NOP sleds), and fingerprints of known steganography tools   
     like OpenStego or OutGuess.
   * Global Intel (VirusTotal): Automatically calculates file hashes (SHA256) and checks them against a database of known malicious files.
