import contextlib
import importlib.util
import io
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).parent
spec_base = importlib.util.spec_from_file_location("create_csr_job", ROOT / "create-csr-job.py")
base = importlib.util.module_from_spec(spec_base)
sys.modules["create_csr_job"] = base
spec_base.loader.exec_module(base)
spec = importlib.util.spec_from_file_location("server_csr", ROOT / "create-server-csr-job.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class ServerCsrTests(unittest.TestCase):
    def run_scenario(self, responses, **overrides):
        with patch.dict(server.os.environ, {"AZURE_CLIENT_ID": overrides.get("identity", server.IDENTITY)}), \
             patch.object(server.socket, "getaddrinfo", return_value=[(None, None, None, None, (overrides.get("ip", "10.20.5.22"), 443))]), \
             patch.object(server, "acquire_token", return_value="test-only"), \
             patch.object(server, "request", side_effect=responses) as request, \
             contextlib.redirect_stdout(io.StringIO()):
            server.main()
            return request.call_args_list

    def test_create_only_server_policy(self):
        calls = self.run_scenario([(404, {}), (404, {}), (404, {}), (202, {"csr": "AQID"})])
        policy = calls[-1].args[2]["policy"]
        self.assertEqual(policy["x509_props"]["sans"]["dns_names"], [server.HOSTNAME])
        self.assertEqual(policy["x509_props"]["ekus"], ["1.3.6.1.5.5.7.3.1"])
        self.assertEqual(policy["key_props"]["key_size"], 3072)
        self.assertFalse(any("/secrets" in c.args[1] or "/keys" in c.args[1] for c in calls))

    def test_existing_certificate_not_overwritten(self):
        with self.assertRaises(server.SafeFailure):
            self.run_scenario([(200, {})])

    def test_permission_failure_no_create(self):
        with self.assertRaises(server.SafeFailure):
            self.run_scenario([(403, {})])

    def test_deleted_certificate_not_overwritten(self):
        with self.assertRaises(server.SafeFailure):
            self.run_scenario([(404, {}), (404, {}), (200, {})])

    def test_create_failure_not_retried(self):
        with self.assertRaises(server.SafeFailure):
            self.run_scenario([(404, {}), (404, {}), (404, {}), (500, {})])

    def test_wrong_identity(self):
        with self.assertRaises(server.SafeFailure):
            self.run_scenario([], identity="different")

    def test_public_dns_rejected(self):
        with self.assertRaises(server.SafeFailure):
            self.run_scenario([], ip="203.0.113.1")

    def test_pending_policy_mismatch(self):
        with self.assertRaises(server.SafeFailure):
            self.run_scenario([(404, {}), (200, {"csr": "AQID"}), (200, {"issuer": {"name": "Self"}})])

    def test_matching_pending_reused_read_only(self):
        policy = {"issuer": {"name": "Unknown"}, "key_props": {"kty": "RSA", "key_size": 3072},
                  "x509_props": {"sans": {"dns_names": [server.HOSTNAME]}, "subject": "CN=" + server.HOSTNAME,
                                 "ekus": ["1.3.6.1.5.5.7.3.1"]}}
        calls = self.run_scenario([(404, {}), (200, {"csr": "AQID"}), (200, policy)])
        self.assertTrue(all(c.args[0] == "GET" for c in calls))


if __name__ == "__main__":
    unittest.main()
