import requests
import time
from config import Config, logger

BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = lambda: {"x-apikey": Config.VIRUSTOTAL_API_KEY}


def _parse_stats(stats: dict) -> dict:
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


def scan_ip(ip: str) -> dict:
    """Scan an IP address against VirusTotal."""
    logger.info(f"VT: Scanning IP {ip}")
    try:
        resp = requests.get(f"{BASE_URL}/ip_addresses/{ip}", headers=HEADERS(), timeout=15)
        if resp.status_code == 429:
            logger.warning("VT: Rate limited, waiting 60s")
            time.sleep(60)
            resp = requests.get(f"{BASE_URL}/ip_addresses/{ip}", headers=HEADERS(), timeout=15)
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = _parse_stats(data.get("last_analysis_stats", {}))
        return {
            "tool": "VirusTotal",
            "type": "ip_scan",
            "ip": ip,
            "stats": stats,
            "reputation": data.get("reputation", 0),
            "country": data.get("country", "Unknown"),
            "as_owner": data.get("as_owner", "Unknown"),
            "total_votes": data.get("total_votes", {}),
            "is_malicious": stats["malicious"] > 0,
            "error": None,
        }
    except requests.RequestException as e:
        logger.error(f"VT IP scan failed: {e}")
        return {"tool": "VirusTotal", "type": "ip_scan", "ip": ip, "error": str(e)}

def scan_url(url: str) -> dict:
    """Submit a URL for scanning."""
    logger.info(f"VT: Scanning URL {url}")
    try:
        resp = requests.post(f"{BASE_URL}/urls", headers=HEADERS(),
                             data={"url": url}, timeout=15)
        if resp.status_code == 429:
            time.sleep(60)
            resp = requests.post(f"{BASE_URL}/urls", headers=HEADERS(),
                                 data={"url": url}, timeout=15)
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]

        # Poll for results (max 30s)
        for _ in range(6):
            time.sleep(5)
            result = requests.get(f"{BASE_URL}/analyses/{analysis_id}",
                                  headers=HEADERS(), timeout=15)
            result.raise_for_status()
            rdata = result.json()["data"]["attributes"]
            if rdata["status"] == "completed":
                stats = _parse_stats(rdata.get("stats", {}))
                return {
                    "tool": "VirusTotal",
                    "type": "url_scan",
                    "url": url,
                    "stats": stats,
                    "is_malicious": stats["malicious"] > 0,
                    "error": None,
                }
        return {"tool": "VirusTotal", "type": "url_scan", "url": url,
                "stats": None, "error": "Analysis timed out"}
    except requests.RequestException as e:
        logger.error(f"VT URL scan failed: {e}")
        return {"tool": "VirusTotal", "type": "url_scan", "url": url, "error": str(e)}


def check_hash(file_hash: str) -> dict:
    """Check a file hash against VirusTotal."""
    logger.info(f"VT: Checking hash {file_hash}")
    try:
        resp = requests.get(f"{BASE_URL}/files/{file_hash}", headers=HEADERS(), timeout=15)
        if resp.status_code == 429:
            time.sleep(60)
            resp = requests.get(f"{BASE_URL}/files/{file_hash}", headers=HEADERS(), timeout=15)
        if resp.status_code == 404:
            return {"tool": "VirusTotal", "type": "hash_check", "hash": file_hash,
                    "error": None, "found": False}
        resp.raise_for_status()
        data = resp.json()["data"]["attributes"]
        stats = _parse_stats(data.get("last_analysis_stats", {}))
        return {
            "tool": "VirusTotal",
            "type": "hash_check",
            "hash": file_hash,
            "found": True,
            "stats": stats,
            "meaningful_name": data.get("meaningful_name", "Unknown"),
            "type_description": data.get("type_description", "Unknown"),
            "is_malicious": stats["malicious"] > 0,
            "error": None,
        }
    except requests.RequestException as e:
        logger.error(f"VT hash check failed: {e}")
        return {"tool": "VirusTotal", "type": "hash_check", "hash": file_hash, "error": str(e)}