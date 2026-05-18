import os
import json

class AICopilot:
    """
    Forensic AI Copilot: Converts complex technical findings into human-readable 
    security summaries using LLMs.
    """
    def __init__(self, api_key=None, base_url=None):
        # Try to get from environment if not provided
        self.api_key = api_key or os.getenv("STEGDEFENDER_AI_KEY")
        self.base_url = base_url or os.getenv("STEGDEFENDER_AI_URL", "https://api.openai.com/v1")
        
    def generate_summary(self, results_tree):
        """
        Main entry point to generate a summary for the forensic tree.
        """
        summary_context = self._extract_key_findings(results_tree)
        
        prompt = f"""
        You are a Senior Digital Forensics Expert. Analyze the following forensic results tree 
        extracted from a suspicious file and provide a concise, high-signal summary for a security analyst.
        
        Key objectives:
        1. Identify the primary threat or artifact.
        2. Explain how the data was hidden (e.g., LSB, EOF, Network Tunneling, Zero-Width Characters).
        3. Recommend specific next steps (e.g., attempt cracking, check VirusTotal, isolate host, analyze network traffic).
        4. Identify if this looks like a known tool footprint (e.g., Steghide, OpenStego).
        
        Structure your response with:
        - **Executive Summary**: One-line verdict.
        - **Detailed Analysis**: What was found and where.
        - **Action Plan**: Immediate next steps for the analyst.

        FORENSIC RESULTS (JSON):
        {json.dumps(summary_context, indent=2)}
        
        SUMMARY:
        """
        
        if not self.api_key:
            return self._generate_heuristic_summary(results_tree)
            
        return self._call_ai(prompt)

    def _extract_key_findings(self, node, depth=0):
        """
        Simplifies the heavy results tree into a lean JSON object for LLM consumption.
        """
        findings = {
            "filename": node["filename"],
            "mime": node["info"]["mime"],
            "verdict": node["findings"]["verdict"],
            "anomalies": [d["message"] for d in node["findings"]["details"] if d["severity"] in ["warning", "danger"]],
            "metadata_highlights": {k: v for k, v in node["findings"].get("metadata", {}).items() if k in ["Software", "Author", "Type", "Capture Format"]},
            "nested_count": len(node.get("nested", [])),
            "nested_artifacts": []
        }
        
        # Limit recursion for the prompt context to keep it lean
        if depth < 5:
            for nest in node.get("nested", []):
                findings["nested_artifacts"].append(self._extract_key_findings(nest["analysis"], depth + 1))
            
        return findings

    def _generate_heuristic_summary(self, results_tree):
        """
        Fallback heuristic summary when no AI API key is available.
        Provides a structured text report based on rules.
        """
        verdict = results_tree["findings"]["verdict"]
        filename = results_tree["filename"]
        mime = results_tree["info"]["mime"]
        
        lines = []
        if verdict == "Stego Detected":
            lines.append(f"### 🚨 Executive Summary: Confirmed Steganography")
            lines.append(f"StegDefender has confirmed the presence of hidden data in `{filename}`.")
        elif verdict == "Suspicious":
            lines.append(f"### ⚠️ Executive Summary: Suspicious Activity")
            lines.append(f"Multiple anomalies were detected in `{filename}` suggesting attempted data hiding.")
        else:
            lines.append(f"### ✅ Executive Summary: Likely Clean")
            lines.append(f"No obvious steganographic signatures were found in `{filename}`.")

        lines.append("\n### Detailed Analysis")
        
        # Primary File Findings
        details = [d["message"] for d in results_tree["findings"]["details"] if d["severity"] in ["warning", "danger"]]
        if details:
            lines.append(f"- **Primary File ({mime})**: Detected {len(details)} critical anomalies.")
            for d in details[:5]:
                lines.append(f"  - {d}")
        else:
            lines.append(f"- **Primary File**: Structure appears standard for {mime}.")

        # Recursion Info
        nested = results_tree.get("nested", [])
        if nested:
            lines.append(f"- **Recursive Extraction**: The engine extracted {len(nested)} hidden layers. This indicates a complex, multi-layered hiding technique (Polyglot/Nesting).")

        lines.append("\n### Action Plan")
        if verdict != "Clean":
            lines.append("1. **Verify Artifacts**: Check the `stegdefender/extracted_data` folder for carved files.")
            if "EOF" in str(details) or "IEND" in str(details):
                lines.append("2. **Manual Carving**: Analyze the appended data for encrypted headers.")
            if results_tree["findings"].get("verdict") == "Suspicious":
                lines.append("3. **Brute Force**: Use the Cracker module with a targeted wordlist.")
        else:
            lines.append("1. **Deeper Scan**: Run with `--depth 5` to check for even deeper hidden layers.")
            
        lines.append("\n---\n*Note: This is an automated heuristic summary. Provide a `STEGDEFENDER_AI_KEY` environment variable to enable the full GPT-4o powered Forensic Copilot.*")
        
        return "\n".join(lines)

    def _call_ai(self, prompt):
        """
        Calls an OpenAI-compatible API to generate the forensic summary.
        """
        try:
            import requests
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": "You are an expert digital forensics AI assistant named StegCopilot."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2
            }
            
            response = requests.post(
                f"{self.base_url}/chat/completions", 
                headers=headers, 
                json=payload, 
                timeout=20
            )
            
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
            else:
                error_msg = f"AI API Error (Status {response.status_code}): {response.text}"
                return f"{self._generate_heuristic_summary(self.last_tree)}\n\n(AI Enhancement Failed: {error_msg})"
                
        except Exception as e:
            return f"Failed to connect to AI Copilot: {str(e)}"
