import os
import logging
import struct
import time
from collections import defaultdict, Counter
from stegdefender.core.analyzer import BaseAnalyzer
from stegdefender.utils.entropy import calculate_entropy

logger = logging.getLogger(__name__)

# --- Constants ---
MAX_PACKETS = 500_000
MAX_STREAM_BYTES = 10 * 1024 * 1024   # 10 MB per stream
MAX_TOTAL_STREAM_BYTES = 50 * 1024 * 1024  # 50 MB total across all streams
ANALYSIS_TIMEOUT_SECONDS = 120

# Magic bytes for file carving inside streams
FILE_SIGNATURES = {
    b'\x50\x4b\x03\x04': ('zip', '.zip'),
    b'\x50\x4b\x05\x06': ('zip_eocd', '.zip'),
    b'\x89PNG\r\n\x1a\n': ('png', '.png'),
    b'\xff\xd8\xff': ('jpeg', '.jpg'),
    b'GIF87a': ('gif', '.gif'),
    b'GIF89a': ('gif', '.gif'),
    b'%PDF': ('pdf', '.pdf'),
    b'MZ': ('pe_exe', '.exe'),
    b'\x7fELF': ('elf', '.elf'),
    b'RIFF': ('riff', '.wav'),
    b'\x1f\x8b': ('gzip', '.gz'),
    b'BM': ('bmp', '.bmp'),
}


class NetworkAnalyzer(BaseAnalyzer):
    """
    Production-grade PCAP/PCAP-NG analyzer with:
    - Memory-safe streaming (caps per-stream and total buffer)
    - Per-packet error isolation (one bad packet doesn't kill analysis)
    - Protocol distribution & top-talker stats
    - ICMP covert-channel detection (entropy + beacon timing)
    - DNS tunneling detection (entropy + length + Base32/64 heuristics)
    - TCP stream file carving by magic bytes
    - HTTP file extraction with Content-Type awareness
    - FTP data channel detection
    - Covert timing analysis (regular-interval beacon detection)
    """

    def analyze(self):
        self.set_verdict("Clean")
        self.results["details"] = []
        self.results["stego_artifacts"] = []
        self.results["metadata"] = {
            "Type": "Network Capture (PCAP)",
        }

        # Accumulators
        self._packet_count = 0
        self._error_count = 0
        self._protocol_counts = Counter()
        self._src_ip_counts = Counter()
        self._dst_ip_counts = Counter()
        self._streams = {}
        self._total_stream_bytes = 0
        self._icmp_timestamps = []
        self._dns_timestamps = []
        self._dns_queries = []
        self._start_time = time.time()

        try:
            self._process_pcap()
        except Exception as e:
            self.add_detail(f"PCAP processing error: {type(e).__name__}: {str(e)}", "warning")
            logger.exception("PCAP processing failed")

        # Post-processing (even if packet reading partially failed)
        try:
            self._generate_statistics()
        except Exception as e:
            self.add_detail(f"Statistics generation error: {str(e)}", "warning")

        try:
            self._analyze_streams()
        except Exception as e:
            self.add_detail(f"Stream analysis error: {str(e)}", "warning")

        try:
            self._check_covert_timing()
        except Exception as e:
            self.add_detail(f"Timing analysis error: {str(e)}", "warning")

        elapsed = round(time.time() - self._start_time, 2)
        self.results["metadata"]["Analysis Duration"] = f"{elapsed}s"

        if self._error_count > 0:
            self.add_detail(
                f"{self._error_count} packets had parse errors (skipped safely).",
                "warning" if self._error_count < 100 else "info"
            )

        return self.results

    # -------------------------------------------------------------------------
    # PCAP Reading — Memory-safe, error-isolated
    # -------------------------------------------------------------------------
    def _process_pcap(self):
        """Read packets using streaming readers, with per-packet error isolation."""
        from scapy.all import TCP, IP, Raw, ICMP, DNS, DNSQR, IPv6, UDP, conf

        # Suppress scapy warnings for malformed packets
        import warnings
        warnings.filterwarnings("ignore", category=Warning)
        conf.verb = 0

        reader = None
        reader_type = None

        # Try PcapReader first (handles .pcap), then PcapNgReader (handles .pcapng)
        try:
            from scapy.utils import PcapReader
            reader = PcapReader(self.file_path)
            reader_type = "pcap"
        except Exception:
            try:
                from scapy.utils import PcapNgReader
                reader = PcapNgReader(self.file_path)
                reader_type = "pcapng"
            except Exception as e:
                self.add_detail(f"Cannot open capture file: {str(e)}", "danger")
                return

        self.results["metadata"]["Capture Format"] = reader_type.upper()

        try:
            for pkt in reader:
                # Timeout guard
                if time.time() - self._start_time > ANALYSIS_TIMEOUT_SECONDS:
                    self.add_detail(
                        f"Analysis timeout ({ANALYSIS_TIMEOUT_SECONDS}s) — stopped at {self._packet_count} packets.",
                        "warning"
                    )
                    break

                # Packet count guard
                if self._packet_count >= MAX_PACKETS:
                    self.add_detail(
                        f"Packet limit ({MAX_PACKETS}) reached — analysis stopped for safety.",
                        "warning"
                    )
                    break

                self._packet_count += 1

                # --- Per-packet isolation ---
                try:
                    self._classify_packet(pkt)
                except Exception:
                    self._error_count += 1
                    continue

                # ICMP Steganography
                try:
                    if ICMP in pkt and pkt[ICMP].type == 8:
                        self._check_icmp_stego(pkt)
                        if hasattr(pkt, 'time'):
                            self._icmp_timestamps.append(float(pkt.time))
                except Exception:
                    self._error_count += 1

                # DNS Steganography
                try:
                    if DNS in pkt and pkt.haslayer(DNSQR):
                        self._check_dns_stego(pkt)
                        if hasattr(pkt, 'time'):
                            self._dns_timestamps.append(float(pkt.time))
                except Exception:
                    self._error_count += 1

                # TCP Stream Reassembly (with memory cap)
                try:
                    if IP in pkt and TCP in pkt and Raw in pkt:
                        self._accumulate_stream(pkt)
                except Exception:
                    self._error_count += 1

                # UDP payload check
                try:
                    if IP in pkt and UDP in pkt and Raw in pkt:
                        payload = bytes(pkt[Raw].load)
                        if len(payload) > 100:
                            ent = calculate_entropy(payload)
                            if ent > 6.5:
                                self._protocol_counts["udp_high_entropy"] += 1
                except Exception:
                    self._error_count += 1

        finally:
            try:
                reader.close()
            except Exception:
                pass

    def _classify_packet(self, pkt):
        """Count protocols for statistics."""
        from scapy.all import TCP, UDP, ICMP, DNS, IP, ARP

        if ARP in pkt:
            self._protocol_counts["ARP"] += 1
        elif ICMP in pkt:
            self._protocol_counts["ICMP"] += 1
        elif DNS in pkt:
            self._protocol_counts["DNS"] += 1
        elif TCP in pkt:
            self._protocol_counts["TCP"] += 1
            # Detect well-known ports
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if 80 in (sport, dport):
                self._protocol_counts["HTTP"] += 1
            elif 443 in (sport, dport):
                self._protocol_counts["HTTPS"] += 1
            elif 21 in (sport, dport):
                self._protocol_counts["FTP"] += 1
            elif 25 in (sport, dport) or 587 in (sport, dport):
                self._protocol_counts["SMTP"] += 1
        elif UDP in pkt:
            self._protocol_counts["UDP"] += 1
        else:
            self._protocol_counts["Other"] += 1

        # Top talkers
        if IP in pkt:
            self._src_ip_counts[pkt[IP].src] += 1
            self._dst_ip_counts[pkt[IP].dst] += 1

    # -------------------------------------------------------------------------
    # ICMP Steganography Detection
    # -------------------------------------------------------------------------
    def _check_icmp_stego(self, pkt):
        """Detects unusual data in ICMP payloads."""
        from scapy.all import Raw, IP

        if Raw not in pkt:
            return

        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            return

        if len(payload) < 16:
            return

        # Normal pings have predictable patterns (abcdefg... or zeros)
        # Check for high entropy or non-standard lengths
        entropy = calculate_entropy(payload)

        # Large payloads with high entropy → covert channel
        if len(payload) > 48 and entropy > 4.5:
            src_ip = pkt[IP].src if IP in pkt else "unknown"
            self.add_detail(
                f"🔴 Suspicious ICMP payload from {src_ip} "
                f"(size={len(payload)}B, entropy={entropy:.2f})",
                "danger"
            )
            self.set_verdict("Stego Detected")
            self.save_artifact(f"icmp_payload_{src_ip}.bin", payload, is_stego=True)

        elif len(payload) > 100:
            # Unusually large ICMP payload even with low entropy
            src_ip = pkt[IP].src if IP in pkt else "unknown"
            self.add_detail(
                f"⚠️ Oversized ICMP payload from {src_ip} "
                f"(size={len(payload)}B, entropy={entropy:.2f})",
                "warning"
            )
            self.set_verdict("Suspicious")

    # -------------------------------------------------------------------------
    # DNS Steganography Detection
    # -------------------------------------------------------------------------
    def _check_dns_stego(self, pkt):
        """Detects DNS tunneling with entropy + length + encoding heuristics."""
        from scapy.all import DNSQR

        try:
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                query_name = qname.decode('utf-8', errors='ignore').rstrip('.')
            else:
                query_name = str(qname).rstrip('.')
        except Exception:
            return

        self._dns_queries.append(query_name)

        parts = query_name.split('.')
        # Skip TLD and SLD — focus on subdomains
        if len(parts) < 3:
            return

        subdomains = parts[:-2]  # everything except domain.tld

        for sub in subdomains:
            if len(sub) < 10:
                continue

            # Length-based detection
            if len(sub) > 32:
                self.add_detail(
                    f"🔴 DNS Tunneling — long subdomain ({len(sub)} chars): {query_name}",
                    "danger"
                )
                self.set_verdict("Stego Detected")
                self.save_artifact("dns_tunnel_query.txt", query_name.encode(), is_stego=True)
                return

            # Entropy-based detection
            sub_bytes = sub.encode('utf-8', errors='ignore')
            entropy = calculate_entropy(sub_bytes)
            if entropy > 3.5 and len(sub) > 16:
                self.add_detail(
                    f"⚠️ High-entropy DNS subdomain (entropy={entropy:.2f}): {query_name}",
                    "warning"
                )
                self.set_verdict("Suspicious")
                return

            # Base32/Base64 heuristic — these encodings use specific character sets
            import re
            if re.match(r'^[A-Z2-7=]+$', sub) and len(sub) > 16:
                self.add_detail(
                    f"🔴 Base32-encoded DNS subdomain detected: {query_name}",
                    "danger"
                )
                self.set_verdict("Stego Detected")
                self.save_artifact("dns_b32_query.txt", query_name.encode(), is_stego=True)
                return
            if re.match(r'^[A-Za-z0-9+/=]+$', sub) and len(sub) > 20:
                self.add_detail(
                    f"⚠️ Possible Base64-encoded DNS subdomain: {query_name}",
                    "warning"
                )
                self.set_verdict("Suspicious")

    # -------------------------------------------------------------------------
    # TCP Stream Reassembly (Memory-Safe)
    # -------------------------------------------------------------------------
    def _accumulate_stream(self, pkt):
        """Accumulate TCP stream data with per-stream and global memory caps."""
        from scapy.all import IP, TCP, Raw

        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        payload = bytes(pkt[Raw].load)

        key = (src, sport, dst, dport)

        # Check global cap
        if self._total_stream_bytes >= MAX_TOTAL_STREAM_BYTES:
            return

        # Per-stream cap
        if key in self._streams:
            current_len = len(self._streams[key])
            if current_len >= MAX_STREAM_BYTES:
                return
            # Trim if adding would exceed
            remaining = MAX_STREAM_BYTES - current_len
            payload = payload[:remaining]
        else:
            self._streams[key] = bytearray()

        self._streams[key].extend(payload)
        self._total_stream_bytes += len(payload)

    # -------------------------------------------------------------------------
    # Stream Analysis — HTTP extraction + file carving
    # -------------------------------------------------------------------------
    def _analyze_streams(self):
        """Analyze accumulated TCP streams for files and anomalies."""
        if not self._streams:
            return

        self.add_detail(f"Reassembled {len(self._streams)} TCP streams.", "info")

        extracted_count = 0
        carved_count = 0

        for key, data in self._streams.items():
            # HTTP file extraction
            try:
                extracted_count += self._extract_http_files(data, key)
            except Exception:
                self._error_count += 1

            # Raw file carving (find embedded files by magic bytes)
            try:
                carved_count += self._carve_files_from_stream(data, key)
            except Exception:
                self._error_count += 1

            # FTP data detection
            try:
                self._check_ftp_data(data, key)
            except Exception:
                pass

        if extracted_count > 0:
            self.add_detail(f"Extracted {extracted_count} files from HTTP streams.", "info")
        if carved_count > 0:
            self.add_detail(f"Carved {carved_count} embedded files from raw TCP streams.", "warning")

    def _extract_http_files(self, stream_data, stream_key):
        """Extract files from HTTP responses with proper handling."""
        count = 0
        try:
            # Split on HTTP response boundaries
            parts = stream_data.split(b"HTTP/1.")
            for idx, part in enumerate(parts):
                if not part:
                    continue

                header_check = b"HTTP/1." + part

                # Only process 200 OK responses
                if b" 200 " not in header_check[:30]:
                    continue

                # Split headers from body
                eoh = header_check.find(b"\r\n\r\n")
                if eoh == -1:
                    continue

                headers_raw = header_check[:eoh].decode('utf-8', errors='ignore')
                body = header_check[eoh + 4:]

                if len(body) < 50:
                    continue

                lower_headers = headers_raw.lower()

                # Determine file type from Content-Type
                ext = ".bin"
                is_interesting = False

                content_type_map = {
                    "image/png": (".png", True),
                    "image/jpeg": (".jpg", True),
                    "image/gif": (".gif", True),
                    "image/bmp": (".bmp", True),
                    "application/pdf": (".pdf", True),
                    "application/zip": (".zip", True),
                    "application/x-rar": (".rar", True),
                    "application/octet-stream": (".bin", True),
                    "text/plain": (".txt", True),
                    "text/html": (".html", False),
                    "application/javascript": (".js", False),
                }

                for ct, (file_ext, interesting) in content_type_map.items():
                    if ct in lower_headers:
                        ext = file_ext
                        is_interesting = interesting
                        break

                # Also interesting if body has known file magic bytes
                if not is_interesting:
                    for sig, (sig_name, sig_ext) in FILE_SIGNATURES.items():
                        if body[:len(sig)] == sig:
                            ext = sig_ext
                            is_interesting = True
                            break

                if is_interesting and len(body) > 100:
                    # Handle chunked transfer encoding
                    if "transfer-encoding: chunked" in lower_headers:
                        body = self._decode_chunked(body)

                    src_ip, src_port, _, _ = stream_key
                    filename = f"http_file_{src_ip}_{count}{ext}"
                    self.save_artifact(filename, body)
                    self.add_detail(
                        f"Extracted HTTP file: {filename} ({len(body)} bytes)",
                        "info"
                    )
                    count += 1

        except Exception as e:
            self.add_detail(f"HTTP extraction error: {str(e)}", "warning")

        return count

    def _decode_chunked(self, data):
        """Decode HTTP chunked transfer encoding."""
        result = bytearray()
        pos = 0
        try:
            while pos < len(data):
                # Find chunk size line
                end_of_size = data.find(b"\r\n", pos)
                if end_of_size == -1:
                    break
                size_str = data[pos:end_of_size].decode('ascii', errors='ignore').strip()
                if not size_str:
                    break
                # Handle chunk extensions (after semicolon)
                if ';' in size_str:
                    size_str = size_str.split(';')[0]
                chunk_size = int(size_str, 16)
                if chunk_size == 0:
                    break
                chunk_start = end_of_size + 2
                chunk_end = chunk_start + chunk_size
                if chunk_end > len(data):
                    # Incomplete chunk — take what we have
                    result.extend(data[chunk_start:])
                    break
                result.extend(data[chunk_start:chunk_end])
                pos = chunk_end + 2  # skip \r\n after chunk
        except (ValueError, IndexError):
            # If chunked decoding fails, return original data
            return data
        return bytes(result) if result else data

    def _carve_files_from_stream(self, stream_data, stream_key):
        """Carve embedded files from raw TCP stream data using magic bytes."""
        count = 0
        data_len = len(stream_data)

        for sig, (sig_name, sig_ext) in FILE_SIGNATURES.items():
            offset = 0
            while offset < data_len and count < 20:  # cap at 20 carved files
                idx = stream_data.find(sig, offset)
                if idx == -1:
                    break

                # Skip if this is at the very start (likely the normal file transfer)
                # Only flag if found mid-stream (embedded/hidden)
                if idx < 4:
                    offset = idx + len(sig)
                    continue

                # Extract a reasonable chunk (up to 5MB or next signature)
                end = min(idx + 5 * 1024 * 1024, data_len)
                carved_data = bytes(stream_data[idx:end])

                if len(carved_data) > 50:
                    src_ip = stream_key[0]
                    filename = f"carved_{sig_name}_{src_ip}_{count}{sig_ext}"
                    self.save_artifact(filename, carved_data)
                    self.add_detail(
                        f"⚠️ Carved embedded {sig_name.upper()} file at stream offset {idx}",
                        "warning"
                    )
                    self.set_verdict("Suspicious")
                    count += 1

                offset = idx + len(sig)

        return count

    def _check_ftp_data(self, stream_data, stream_key):
        """Detect FTP data channel transfers."""
        src_ip, sport, dst_ip, dport = stream_key

        # FTP data ports are typically >1024 and FTP control is on 21
        # Check if other streams from same IPs use port 21
        has_ftp_control = any(
            k[2] == dst_ip and (k[3] == 21 or k[1] == 21)
            for k in self._streams.keys()
        )

        if has_ftp_control and len(stream_data) > 1000:
            self.add_detail(
                f"FTP data transfer detected: {src_ip}:{sport} → {dst_ip}:{dport} "
                f"({len(stream_data)} bytes)",
                "warning"
            )
            # Check entropy of the FTP data
            entropy = calculate_entropy(stream_data[:4096])
            if entropy > 7.0:
                self.add_detail(
                    f"FTP data has high entropy ({entropy:.2f}) — possible encrypted/compressed file",
                    "warning"
                )
                self.set_verdict("Suspicious")

    # -------------------------------------------------------------------------
    # Covert Channel Timing Analysis
    # -------------------------------------------------------------------------
    def _check_covert_timing(self):
        """Detect beacon-like regular intervals in ICMP/DNS traffic."""
        for proto, timestamps in [("ICMP", self._icmp_timestamps), ("DNS", self._dns_timestamps)]:
            if len(timestamps) < 10:
                continue

            timestamps.sort()
            intervals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]

            if not intervals:
                continue

            avg_interval = sum(intervals) / len(intervals)

            if avg_interval <= 0:
                continue

            # Check coefficient of variation (std_dev / mean)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            std_dev = variance ** 0.5

            cv = std_dev / avg_interval if avg_interval > 0 else float('inf')

            # Very regular intervals (CV < 0.15) suggest automated beaconing
            if cv < 0.15 and avg_interval < 5.0:
                self.add_detail(
                    f"🔴 {proto} beacon pattern detected — {len(timestamps)} packets at "
                    f"~{avg_interval:.2f}s intervals (CV={cv:.3f})",
                    "danger"
                )
                self.set_verdict("Stego Detected")
            elif cv < 0.3 and avg_interval < 10.0:
                self.add_detail(
                    f"⚠️ Possible {proto} beacon — {len(timestamps)} packets at "
                    f"~{avg_interval:.2f}s intervals (CV={cv:.3f})",
                    "warning"
                )
                self.set_verdict("Suspicious")

    # -------------------------------------------------------------------------
    # Statistics Generation
    # -------------------------------------------------------------------------
    def _generate_statistics(self):
        """Generate protocol distribution and top-talker statistics."""
        self.results["metadata"]["Packets Processed"] = self._packet_count
        self.results["metadata"]["TCP Streams"] = len(self._streams)
        self.results["metadata"]["Stream Data"] = f"{self._total_stream_bytes:,} bytes"

        self.add_detail(f"Processed {self._packet_count} network packets.", "info")

        # Protocol distribution
        if self._protocol_counts:
            proto_str = ", ".join(
                f"{proto}: {count}"
                for proto, count in self._protocol_counts.most_common(10)
            )
            self.add_detail(f"Protocol distribution: {proto_str}", "info")
            self.results["metadata"]["Protocols"] = dict(self._protocol_counts.most_common(10))

        # Top talkers
        if self._src_ip_counts:
            top_src = self._src_ip_counts.most_common(5)
            top_str = ", ".join(f"{ip} ({cnt} pkts)" for ip, cnt in top_src)
            self.add_detail(f"Top sources: {top_str}", "info")
            self.results["metadata"]["Top Sources"] = dict(top_src)

        if self._dst_ip_counts:
            top_dst = self._dst_ip_counts.most_common(5)
            top_str = ", ".join(f"{ip} ({cnt} pkts)" for ip, cnt in top_dst)
            self.add_detail(f"Top destinations: {top_str}", "info")
            self.results["metadata"]["Top Destinations"] = dict(top_dst)

        # DNS query summary
        if self._dns_queries:
            unique_domains = set()
            for q in self._dns_queries:
                parts = q.split('.')
                if len(parts) >= 2:
                    unique_domains.add('.'.join(parts[-2:]))
            self.results["metadata"]["Unique DNS Domains"] = len(unique_domains)
            self.add_detail(f"DNS queries: {len(self._dns_queries)} total, "
                          f"{len(unique_domains)} unique domains.", "info")

        # High-entropy UDP packets
        if self._protocol_counts.get("udp_high_entropy", 0) > 5:
            self.add_detail(
                f"⚠️ {self._protocol_counts['udp_high_entropy']} UDP packets with "
                f"high-entropy payloads detected.",
                "warning"
            )
            self.set_verdict("Suspicious")
