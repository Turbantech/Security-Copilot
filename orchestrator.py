import json
from openai import OpenAI
from threat_scorer import calculate_threat_score, format_threat_score_block
from config import Config, logger
from system_prompt import SYSTEM_PROMPT
from tools import virustotal_tool, abuseipdb_tool, greynoise_tool, shodan_tool, mitre_tool

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "scan_ip_virustotal",
            "description": "Scan an IP address using VirusTotal for malware detections",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string", "description": "IP address to scan"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_url_virustotal",
            "description": "Scan a URL using VirusTotal for malware detections",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "URL to scan"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_hash_virustotal",
            "description": "Check a file hash (MD5/SHA1/SHA256) using VirusTotal",
            "parameters": {
                "type": "object",
                "properties": {"file_hash": {"type": "string", "description": "File hash to check"}},
                "required": ["file_hash"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_ip_abuseipdb",
            "description": "Check an IP for abuse reports using AbuseIPDB",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string", "description": "IP address to check"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_ip_greynoise",
            "description": "Check if an IP is internet background noise or targeted threat using GreyNoise",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string", "description": "IP address to check"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_ip_shodan",
            "description": "Look up an IP on Shodan for open ports, services, and vulnerabilities",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string", "description": "IP address to look up"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mitre_get_technique",
            "description": "Get a MITRE ATT&CK technique by its ID (e.g., T1059)",
            "parameters": {
                "type": "object",
                "properties": {"technique_id": {"type": "string", "description": "MITRE technique ID"}},
                "required": ["technique_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mitre_get_by_tactic",
            "description": "Get MITRE ATT&CK techniques for a specific tactic (e.g., initial-access, persistence)",
            "parameters": {
                "type": "object",
                "properties": {"tactic": {"type": "string", "description": "Tactic name"}},
                "required": ["tactic"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mitre_get_by_platform",
            "description": "Get MITRE ATT&CK techniques for a platform (Windows, Linux, macOS)",
            "parameters": {
                "type": "object",
                "properties": {"platform": {"type": "string", "description": "Platform name"}},
                "required": ["platform"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mitre_search",
            "description": "Search MITRE ATT&CK techniques by keyword (e.g., credential dumping, phishing)",
            "parameters": {
                "type": "object",
                "properties": {"keyword": {"type": "string", "description": "Search keyword"}},
                "required": ["keyword"],
            },
        },
    },
]

FUNCTION_MAP = {
    "scan_ip_virustotal": lambda args: virustotal_tool.scan_ip(args["ip"]),
    "scan_url_virustotal": lambda args: virustotal_tool.scan_url(args["url"]),
    "check_hash_virustotal": lambda args: virustotal_tool.check_hash(args["file_hash"]),
    "check_ip_abuseipdb": lambda args: abuseipdb_tool.check_ip(args["ip"]),
    "check_ip_greynoise": lambda args: greynoise_tool.check_ip(args["ip"]),
    "lookup_ip_shodan": lambda args: shodan_tool.lookup_ip(args["ip"]),
    "mitre_get_technique": lambda args: mitre_tool.get_technique(args["technique_id"]),
    "mitre_get_by_tactic": lambda args: mitre_tool.get_techniques_by_tactic(args["tactic"]),
    "mitre_get_by_platform": lambda args: mitre_tool.get_techniques_by_platform(args["platform"]),
    "mitre_search": lambda args: mitre_tool.search_techniques(args["keyword"]),
}


class SecurityCopilot:
    def __init__(self):
        self.client = OpenAI(api_key=Config.OPENAI_API_KEY)
        self.conversation_history = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.last_scan_data = {}
        logger.info("SecurityCopilot initialized")

    def reset(self):
            self.conversation_history = [{"role": "system", "content": SYSTEM_PROMPT}]
            self.last_scan_data = {}

    def get_last_scan_data(self) -> dict:
        """Extract the most recent scan data for report generation."""
        vt_result = None
        abuseipdb_result = None
        greynoise_result = None
        shodan_result = None
        indicator = None
        indicator_type = "IP"
    
        for msg in self.conversation_history:
            if not isinstance(msg, dict):
                continue
            if msg.get("role") != "tool":
                continue
            try:
                data = json.loads(msg.get("content", "{}"))
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            
            if data.get("tool") == "VirusTotal":
                vt_result = data
                indicator = data.get("ip") or data.get("url") or data.get("hash")
                if data.get("type") == "url_scan":
                    indicator_type = "URL"
                elif data.get("type") == "hash_scan":
                    indicator_type = "File Hash"
                else:
                    indicator_type = "IP Address"
            if data.get("tool") == "AbuseIPDB":
                abuseipdb_result = data
                indicator = indicator or data.get("ip")
            if data.get("tool") == "GreyNoise":
                greynoise_result = data
            if data.get("tool") == "Shodan":
                shodan_result = data
    
        # Get last assistant message as AI summary
        ai_summary = ""
        for msg in reversed(self.conversation_history):
            if not isinstance(msg, dict):
                if hasattr(msg, "role") and msg.role == "assistant":
                    ai_summary = msg.content or ""
                    break
            elif msg.get("role") == "assistant":
                ai_summary = msg.get("content", "")
                break
            
        # Get threat score
        threat_score = {}
        if any([vt_result, abuseipdb_result, greynoise_result, shodan_result]):
            from threat_scorer import calculate_threat_score
            threat_score = calculate_threat_score(
                vt_result=vt_result,
                abuseipdb_result=abuseipdb_result,
                greynoise_result=greynoise_result,
                shodan_result=shodan_result,
            )
    
        return {
            "indicator": indicator or "Unknown",
            "indicator_type": indicator_type,
            "vt_result": vt_result,
            "abuseipdb_result": abuseipdb_result,
            "greynoise_result": greynoise_result,
            "shodan_result": shodan_result,
            "threat_score": threat_score,
            "ai_summary": ai_summary,
        }

    def chat(self, user_message: str) -> str:
        """Process a user message and return the assistant's response."""
        logger.info(f"User: {user_message}")
        self.conversation_history.append({"role": "user", "content": user_message})

        response = self.client.chat.completions.create(
            model="gpt-4o",
            messages=self.conversation_history,
            tools=TOOL_DEFINITIONS,
            tool_choice="auto",
        )

        message = response.choices[0].message

        while message.tool_calls:
            self.conversation_history.append(message)

            for tool_call in message.tool_calls:
                fn_name = tool_call.function.name
                fn_args = json.loads(tool_call.function.arguments)
                logger.info(f"Calling tool: {fn_name} with {fn_args}")

                if fn_name in FUNCTION_MAP:
                    result = FUNCTION_MAP[fn_name](fn_args)
                else:
                    result = {"error": f"Unknown tool: {fn_name}"}

                self.conversation_history.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result, default=str),
                })

            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=self.conversation_history,
                tools=TOOL_DEFINITIONS,
                tool_choice="auto",
            )
            message = response.choices[0].message

        assistant_reply = message.content or "I couldn't generate a response. Please try again."

        threat_block = self._maybe_generate_threat_score()
        if threat_block:
            assistant_reply = assistant_reply + "\n\n" + threat_block

        self.conversation_history.append({"role": "assistant", "content": assistant_reply})
        logger.info(f"Assistant: {assistant_reply[:100]}...")
        return assistant_reply

    def _maybe_generate_threat_score(self) -> str:
            vt_result = None
            abuseipdb_result = None
            greynoise_result = None
            shodan_result = None
        
            for msg in self.conversation_history:
                # Only process plain dict messages with role "tool"
                if not isinstance(msg, dict):
                    continue
                if msg.get("role") != "tool":
                    continue
                
                content = msg.get("content", "{}")
                if not content:
                    continue
                
                try:
                    data = json.loads(content)
                except Exception:
                    continue
                
                if not isinstance(data, dict):
                    continue
                
                logger.info(f"SCORING - processing tool result: {content[:200]}")
        
                # VirusTotal
                if data.get("tool") == "VirusTotal":
                    vt_result = data
                    continue
                
                # AbuseIPDB
                if data.get("tool") == "AbuseIPDB" or "abuse_confidence_score" in data or "abuseConfidenceScore" in data:
                    abuseipdb_result = data
                    continue
                
                # GreyNoise
                if data.get("tool") == "GreyNoise" or "noise" in data or "classification" in data:
                    greynoise_result = data
                    continue
                
                # Shodan
                if data.get("tool") == "Shodan" or "ports" in data or "vulns" in data:
                    shodan_result = data
                    continue
                
            logger.info(f"SCORING - vt={vt_result is not None} abuse={abuseipdb_result is not None} gn={greynoise_result is not None} shodan={shodan_result is not None}")
        
            if any([vt_result, abuseipdb_result, greynoise_result, shodan_result]):
                score_result = calculate_threat_score(
                    vt_result=vt_result,
                    abuseipdb_result=abuseipdb_result,
                    greynoise_result=greynoise_result,
                    shodan_result=shodan_result,
                )
                return format_threat_score_block(score_result)
        
            return ""