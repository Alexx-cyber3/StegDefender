import os
import logging
from scapy.all import rdpcap, TCP, IP, Raw, ICMP, DNS, DNSQR
from stegdefender.core.analyzer import BaseAnalyzer
from stegdefender.utils.entropy import calculate_entropy

class NetworkAnalyzer(BaseAnalyzer):
    def analyze(self):
        self.set_verdict("Clean")
        self.results["details"] = []
        
        try:
            from scapy.utils import PcapReader
            
            packet_count = 0
            streams = {} 
            
            with PcapReader(self.file_path) as pcap_reader:
                for pkt in pcap_reader:
                    packet_count += 1
                    
                    # 1. Detect ICMP Steganography (Data in Echo Requests)
                    if ICMP in pkt and pkt[ICMP].type == 8: # Echo Request
                        self._check_icmp_stego(pkt)
                    
                    # 2. Detect DNS Steganography (Data in Queries)
                    if DNS in pkt and pkt.haslayer(DNSQR):
                        self._check_dns_stego(pkt)

                    # 3. Reassemble TCP Streams for File Extraction
                    if IP in pkt and TCP in pkt and Raw in pkt:
                        src, dst = pkt[IP].src, pkt[IP].dst
                        sport, dport = pkt[TCP].sport, pkt[TCP].dport
                        payload = pkt[Raw].load
                        key = (src, sport, dst, dport)
                        if key not in streams: streams[key] = bytearray()
                        streams[key].extend(payload)

            self.add_detail(f"Processed {packet_count} network packets.", "info")
            
            # 4. Extract Artifacts from Streams
            extracted_count = 0
            for key, data in streams.items():
                extracted_count += self._extract_http_files(data, key)
                
            if extracted_count > 0:
                self.add_detail(f"Extracted {extracted_count} files for deep inspection.", "info")

        except Exception as e:
            self.add_detail(f"Network analysis failed: {str(e)}", "warning")
            
        return self.results

    def _check_icmp_stego(self, pkt):
        """Detects unusual data in ICMP payloads."""
        if Raw in pkt:
            payload = pkt[Raw].load
            # Normal pings have standard patterns (e.g., abcdefg... or zeros)
            # High entropy or long non-standard payloads are suspicious.
            if len(payload) > 48:
                entropy = calculate_entropy(payload)
                if entropy > 4.0:
                    self.add_detail(f"Suspicious ICMP Payload detected (Entropy: {entropy:.2f})", "danger")
                    self.set_verdict("Stego Detected")
                    self.save_artifact(f"icmp_payload_{pkt[IP].src}.bin", payload)

    def _check_dns_stego(self, pkt):
        """Detects DNS Tunneling or encoded data in subdomains."""
        query_name = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
        # Look for long, high-entropy subdomains (e.g., a1b2c3d4.malicious.com)
        parts = query_name.split('.')
        for part in parts:
            if len(part) > 32:
                self.add_detail(f"Possible DNS Steganography/Tunneling: {query_name}", "danger")
                self.set_verdict("Stego Detected")
                self.save_artifact("dns_query.txt", query_name.encode())

    def _extract_http_files(self, stream_data, stream_key):
        count = 0
        try:
            parts = stream_data.split(b"HTTP/1.")
            for part in parts:
                if not part: continue
                header_check = b"HTTP/1." + part
                if b" 200 OK" not in header_check[:20]: continue
                eoh = header_check.find(b"\r\n\r\n")
                if eoh == -1: continue
                
                headers_raw = header_check[:eoh].decode('utf-8', errors='ignore')
                body = header_check[eoh+4:]
                
                is_interesting = False
                ext = ".bin"
                lower_headers = headers_raw.lower()
                
                if "content-type: image/" in lower_headers:
                    ext = ".png" if "png" in lower_headers else ".jpg"
                    is_interesting = True
                elif "content-type: application/pdf" in lower_headers:
                    ext = ".pdf"; is_interesting = True
                elif "content-type: application/zip" in lower_headers:
                    ext = ".zip"; is_interesting = True
                elif "content-type: text/plain" in lower_headers:
                    ext = ".txt"; is_interesting = True
                
                if is_interesting and len(body) > 100:
                    src_ip, src_port, _, _ = stream_key
                    filename = f"network_file_{count}{ext}"
                    # We save it but DON'T set verdict to "Stego Detected" yet.
                    # The ForensicEngine will analyze the file and set the verdict if stego is found.
                    self.save_artifact(filename, body)
                    count += 1
        except: pass
        return count
