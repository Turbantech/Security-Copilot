import os
import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    filename="security_copilot.log",
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("SecurityCopilot")

class Config:
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

    @classmethod
    def validate(cls):
        missing = []
        for key in ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY",
                     "SHODAN_API_KEY", "OPENAI_API_KEY"]:
            if not getattr(cls, key):
                missing.append(key)
        return missing

    @classmethod
    def get_status(cls):
        """Returns dict of tool name -> connected boolean."""
        return {
            "VirusTotal": bool(cls.VIRUSTOTAL_API_KEY),
            "AbuseIPDB": bool(cls.ABUSEIPDB_API_KEY),
            "GreyNoise": bool(cls.GREYNOISE_API_KEY),
            "Shodan": bool(cls.SHODAN_API_KEY),
            "MITRE ATT&CK": True,  # No API key needed
            "OpenAI": bool(cls.OPENAI_API_KEY),
        }