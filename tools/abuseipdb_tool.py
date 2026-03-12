import requests
from config import Config, logger

BASE_URL = "https://api.abuseipdb.com/api/v2"


def check_ip(ip: str, max_age_days: int = 90) -> dict:
    """Check an IP against AbuseIPDB for abuse reports."""
    logger.info(f"AbuseIPDB: Checking IP {ip}")
    try:
        resp = requests.get(
            f"{BASE_URL}/check",
            headers={
                "Key": Config.ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "tool": "AbuseIPDB",
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "domain": data.get("domain", "Unknown"),
            "is_whitelisted": data.get("isWhitelisted", False),
            "is_tor": data.get("isTor", False),
            "usage_type": data.get("usageType", "Unknown"),
            "last_reported": data.get("lastReportedAt", None),
            "is_abusive": data.get("abuseConfidenceScore", 0) > 25,
            "error": None,
        }
    except requests.RequestException as e:
        logger.error(f"AbuseIPDB check failed: {e}")
        return {"tool": "AbuseIPDB", "ip": ip, "error": str(e)}