import os
import unittest
from unittest.mock import patch
from agent import vuln_ports
from agent.severity_policy import cvss_severity

class EnvCatalogTests(unittest.TestCase):
    def tearDown(self):
        vuln_ports.service_registry.cache_clear()
        vuln_ports.port_document.cache_clear()

    def test_service_registry_has_52_rows(self):
        self.assertEqual(len(vuln_ports.service_registry()), 52)

    def test_cvss_boundaries(self):
        self.assertEqual(
            [cvss_severity(x) for x in (0, 0.1, 3.9, 4, 5.9, 6, 7.9, 8, 10)],
            ["None", "Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"],
        )

    def test_extra_tcp_and_udp_config(self):
        with patch.dict(os.environ, {"SERVICE_EXTRA_TCP_PORTS":"12345", "SERVICE_EXTRA_UDP_PORTS":"12346"}):
            vuln_ports.port_document.cache_clear()
            doc=vuln_ports.port_document()
            self.assertIn("12345",{row["ports"] for row in doc["tcp"]})
            self.assertIn("12346",{row["ports"] for row in doc["udp"]})

    def test_bad_port_is_rejected(self):
        with self.assertRaises(ValueError):
            vuln_ports.parse_ports("65536")
