import shodan
from config import Config, logger


def lookup_ip(ip: str) -> dict:
    """Look up an IP on Shodan for open ports, services, and vulnerabilities."""
    logger.info(f"Shodan: Looking up IP {ip}")
    try:
        api = shodan.Shodan(Config.SHODAN_API_KEY)
        result = api.host(ip)
        services = []
        for item in result.get("data", []):
            services.append({
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", "Unknown"),
                "version": item.get("version", ""),
            })
        return {
            "tool": "Shodan",
            "ip": ip,
            "hostnames": result.get("hostnames", []),
            "os": result.get("os", "Unknown"),
            "ports": result.get("ports", []),
            "vulns": result.get("vulns", []),
            "services": services,
            "city": result.get("city", "Unknown"),
            "country_name": result.get("country_name", "Unknown"),
            "isp": result.get("isp", "Unknown"),
            "org": result.get("org", "Unknown"),
            "error": None,
        }
    except shodan.APIError as e:
        logger.error(f"Shodan lookup failed: {e}")
        return {"tool": "Shodan", "ip": ip, "error": str(e)}