"""Unit tests with mocked API responses."""
import unittest
from unittest.mock import patch, MagicMock
from tools import virustotal_tool, abuseipdb_tool, greynoise_tool, mitre_tool


class TestVirusTotal(unittest.TestCase):
    @patch("tools.virustotal_tool.requests.get")
    def test_scan_ip_success(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10},
                        "reputation": -5,
                        "country": "RU",
                        "as_owner": "Evil Corp",
                        "total_votes": {"malicious": 3, "harmless": 0},
                    }
                }
            },
        )
        mock_get.return_value.raise_for_status = MagicMock()
        result = virustotal_tool.scan_ip("1.2.3.4")
        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["stats"]["malicious"], 5)
        self.assertIsNone(result["error"])

    @patch("tools.virustotal_tool.requests.get")
    def test_scan_ip_error(self, mock_get):
        mock_get.side_effect = Exception("Connection failed")
        result = virustotal_tool.scan_ip("1.2.3.4")
        self.assertIsNotNone(result["error"])


class TestAbuseIPDB(unittest.TestCase):
    @patch("tools.abuseipdb_tool.requests.get")
    def test_check_ip(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "data": {
                    "abuseConfidenceScore": 85,
                    "totalReports": 47,
                    "countryCode": "CN",
                    "isp": "Bad ISP",
                }
            },
        )
        mock_get.return_value.raise_for_status = MagicMock()
        result = abuseipdb_tool.check_ip("1.2.3.4")
        self.assertTrue(result["is_abusive"])
        self.assertEqual(result["abuse_confidence_score"], 85)


class TestGreyNoise(unittest.TestCase):
    @patch("tools.greynoise_tool.requests.get")
    def test_check_ip_noise(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "noise": True,
                "riot": False,
                "classification": "malicious",
                "name": "Known Scanner",
            },
        )
        mock_get.return_value.raise_for_status = MagicMock()
        result = greynoise_tool.check_ip("1.2.3.4")
        self.assertTrue(result["noise"])
        self.assertEqual(result["classification"], "malicious")


class TestMITRE(unittest.TestCase):
    @patch("tools.mitre_tool._load_attack_data")
    def test_get_technique_by_id(self, mock_load):
        mock_load.return_value = [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "description": "...",
             "platforms": ["Windows"], "tactics": ["execution"], "url": "", "is_subtechnique": False, "detection": ""},
        ]
        result = mitre_tool.get_technique_by_id("T1059")
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["name"], "Command and Scripting Interpreter")


if __name__ == "__main__":
    unittest.main()