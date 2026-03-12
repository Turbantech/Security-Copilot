# threat_scorer.py

def calculate_threat_score(
    vt_result: dict = None,
    abuseipdb_result: dict = None,
    greynoise_result: dict = None,
    shodan_result: dict = None,
) -> dict:
    score = 0
    evidence = []

    # --- VirusTotal scoring ---
    if vt_result and not vt_result.get("error"):
        stats = vt_result.get("stats", vt_result)
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 20:
            score += 40
            evidence.append(f"VirusTotal: {malicious} engines flagged as malicious (CRITICAL)")
        elif malicious >= 10:
            score += 30
            evidence.append(f"VirusTotal: {malicious} engines flagged as malicious (HIGH)")
        elif malicious >= 3:
            score += 20
            evidence.append(f"VirusTotal: {malicious} engines flagged as malicious (MEDIUM)")
        elif malicious >= 1:
            score += 10
            evidence.append(f"VirusTotal: {malicious} engine flagged as malicious (LOW)")
        else:
            evidence.append("VirusTotal: Clean")

        if suspicious >= 5:
            score += 10
            evidence.append(f"VirusTotal: {suspicious} engines flagged suspicious")
        elif suspicious >= 1:
            score += 5
            evidence.append(f"VirusTotal: {suspicious} engines flagged suspicious")

    # --- AbuseIPDB scoring ---
    if abuseipdb_result and not abuseipdb_result.get("error"):
        confidence = abuseipdb_result.get("abuse_confidence_score") or abuseipdb_result.get("abuseConfidenceScore", 0)
        total_reports = abuseipdb_result.get("total_reports") or abuseipdb_result.get("totalReports", 0)

        if confidence >= 80:
            score += 25
            evidence.append(f"AbuseIPDB: {confidence}% confidence, {total_reports} reports (CRITICAL)")
        elif confidence >= 50:
            score += 15
            evidence.append(f"AbuseIPDB: {confidence}% confidence, {total_reports} reports (HIGH)")
        elif confidence >= 20:
            score += 8
            evidence.append(f"AbuseIPDB: {confidence}% confidence, {total_reports} reports (MEDIUM)")
        elif confidence >= 1:
            score += 3
            evidence.append(f"AbuseIPDB: {confidence}% confidence, {total_reports} reports (LOW)")
        else:
            evidence.append("AbuseIPDB: No abuse reports")

    # --- GreyNoise scoring ---
    if greynoise_result and not greynoise_result.get("error"):
        classification = greynoise_result.get("classification", "unknown")
        noise = greynoise_result.get("noise", False)
        riot = greynoise_result.get("riot", False)

        if classification == "malicious":
            score += 20
            evidence.append("GreyNoise: Classified as MALICIOUS")
        elif riot:
            score -= 10
            evidence.append("GreyNoise: Known benign service (RIOT) — reduces score")
        elif noise:
            score += 8
            evidence.append("GreyNoise: Internet scanner / background noise")
        else:
            evidence.append(f"GreyNoise: Not observed scanning (classification: {classification})")

    # --- Shodan scoring ---
    if shodan_result and not shodan_result.get("error"):
        ports = shodan_result.get("ports", [])
        vulns = shodan_result.get("vulns", [])

        if vulns:
            score += 15
            evidence.append(f"Shodan: {len(vulns)} vulnerabilities detected ({', '.join(list(vulns)[:3])})")
        if 4444 in ports or 1337 in ports or 31337 in ports:
            score += 10
            evidence.append(f"Shodan: Suspicious ports open — {ports}")
        elif ports:
            evidence.append(f"Shodan: Open ports — {ports[:8]}")
        else:
            evidence.append("Shodan: No open ports found")

    # --- Clamp score ---
    score = max(0, min(score, 100))

    # --- Verdict ---
    if score >= 75:
        verdict = "CRITICAL"
        color = "🔴"
        recommendation = "Block immediately. Investigate all connections to/from this indicator."
    elif score >= 50:
        verdict = "HIGH"
        color = "🟠"
        recommendation = "High priority investigation. Consider blocking pending review."
    elif score >= 25:
        verdict = "MEDIUM"
        color = "🟡"
        recommendation = "Monitor closely. Investigate if seen in internal logs."
    elif score >= 1:
        verdict = "LOW"
        color = "🟢"
        recommendation = "Low risk. Keep monitoring but likely not an active threat."
    else:
        verdict = "CLEAN"
        color = "✅"
        recommendation = "No threat indicators found. Continue normal monitoring."

    return {
        "score": score,
        "verdict": verdict,
        "color": color,
        "recommendation": recommendation,
        "evidence": evidence,
    }


def format_threat_score_block(score_result: dict) -> str:
    lines = [
        "---",
        f"## {score_result['color']} Threat Verdict: {score_result['verdict']}",
        f"**Threat Score: {score_result['score']} / 100**",
        "",
        "**Evidence:**",
    ]
    for e in score_result["evidence"]:
        lines.append(f"- {e}")

    lines += [
        "",
        f"**Recommendation:** {score_result['recommendation']}",
        "---",
    ]
    return "\n".join(lines)