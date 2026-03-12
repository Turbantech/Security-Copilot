import requests
from config import Config, logger

COMMUNITY_URL = "https://api.greynoise.io/v3/community"


def check_ip(ip: str) -> dict:
    """Check an IP against GreyNoise to determine if it's internet noise or targeted."""
    logger.info(f"GreyNoise: Checking IP {ip}")
    try:
        resp = requests.get(
            f"{COMMUNITY_URL}/{ip}",
            headers={"key": Config.GREYNOISE_API_KEY, "Accept": "application/json"},
            timeout=15,
        )
        if resp.status_code == 404:
            return {
                "tool": "GreyNoise",
                "ip": ip,
                "noise": False,
                "riot": False,
                "classification": "unknown",
                "name": "Not seen",
                "message": "IP not observed scanning the internet",
                "error": None,
            }
        resp.raise_for_status()
        data = resp.json()
        return {
            "tool": "GreyNoise",
            "ip": ip,
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "name": data.get("name", "Unknown"),
            "message": data.get("message", ""),
            "last_seen": data.get("last_seen", ""),
            "error": None,
        }
    except requests.RequestException as e:
        logger.error(f"GreyNoise check failed: {e}")
        return {"tool": "GreyNoise", "ip": ip, "error": str(e)}
