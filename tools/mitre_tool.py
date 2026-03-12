# tools/mitre_tool.py
import requests
import logging
import json
import os

logger = logging.getLogger(__name__)

# Official MITRE ATT&CK Enterprise JSON feed (no API key needed)
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_FILE = "mitre_cache.json"

_techniques = []


def _load_mitre_data():
    """
    Fetch real MITRE ATT&CK Enterprise data.
    Uses disk cache after first download to avoid repeated fetches.
    """
    global _techniques

    if _techniques:
        return _techniques

    # Load from cache if available
    if os.path.exists(CACHE_FILE):
        logger.info("Loading MITRE data from local cache...")
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            _techniques = json.load(f)
        logger.info(f"Loaded {len(_techniques)} techniques from cache")
        return _techniques

    # Fetch fresh from MITRE GitHub (official source)
    logger.info("Fetching MITRE ATT&CK data from official source (first run, takes ~30s)...")
    try:
        resp = requests.get(MITRE_URL, timeout=60)
        resp.raise_for_status()
        raw = resp.json()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch MITRE data: {e}")
        return []

    parsed = []
    for obj in raw.get("objects", []):
        # Only process attack-pattern objects (techniques)
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Extract technique ID (e.g. T1059)
        tech_id = ""
        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        if not tech_id:
            continue

        # Extract tactics
        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        parsed.append({
            "id": tech_id,
            "name": obj.get("name", ""),
            "description": (obj.get("description", "") or "")[:600],
            "platforms": obj.get("x_mitre_platforms", []),
            "tactics": tactics,
            "detection": (obj.get("x_mitre_detection", "") or "")[:400],
            "url": url,
            "is_subtechnique": "." in tech_id,
        })

    _techniques = parsed

    # Save to disk cache
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(_techniques, f)

    logger.info(f"Fetched and cached {len(_techniques)} real MITRE ATT&CK techniques")
    return _techniques


def get_technique(technique_id: str) -> dict:
    """Look up a specific technique by ID (e.g. T1059 or T1059.001)."""
    techniques = _load_mitre_data()
    technique_id = technique_id.strip().upper()

    for t in techniques:
        if t["id"] == technique_id:
            return t

    return {"error": f"Technique {technique_id} not found in MITRE ATT&CK"}


def get_techniques_by_tactic(tactic: str) -> list:
    """
    Get techniques for a given tactic.
    Example tactics: initial-access, persistence, privilege-escalation,
    defense-evasion, credential-access, discovery, lateral-movement,
    collection, command-and-control, exfiltration, impact, execution
    """
    techniques = _load_mitre_data()
    tactic_normalized = tactic.lower().strip().replace(" ", "-")

    results = [
        {
            "id": t["id"],
            "name": t["name"],
            "tactics": t["tactics"],
            "platforms": t["platforms"],
            "description": t["description"][:200],
        }
        for t in techniques
        if any(tactic_normalized in tac for tac in t["tactics"])
        and not t["is_subtechnique"]  # top-level only for cleaner output
    ]

    return results[:20]


def search_techniques(keyword: str) -> list:
    """Search techniques by keyword in name or description."""
    techniques = _load_mitre_data()
    keyword_lower = keyword.lower().strip()

    results = [
        {
            "id": t["id"],
            "name": t["name"],
            "tactics": t["tactics"],
            "description": t["description"][:250],
            "url": t["url"],
        }
        for t in techniques
        if keyword_lower in t["name"].lower() or keyword_lower in t["description"].lower()
    ]

    return results[:15]


def get_techniques_by_platform(platform: str) -> list:
    """Get techniques targeting a specific platform (Windows, Linux, macOS, etc.)."""
    techniques = _load_mitre_data()
    platform_lower = platform.lower().strip()

    results = [
        {
            "id": t["id"],
            "name": t["name"],
            "tactics": t["tactics"],
            "description": t["description"][:200],
        }
        for t in techniques
        if any(platform_lower in p.lower() for p in t["platforms"])
        and not t["is_subtechnique"]
    ]

    return results[:25]
