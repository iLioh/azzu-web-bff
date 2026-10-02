import base64
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
spec = importlib.util.spec_from_file_location("server_merge", ROOT / "merge-server-csr-job.py")
merge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge)
EXPIRY = 1798733047


def bundle(der=b"test-certificate", **overrides):
    return {"id": merge.BASE + "/certificates/" + merge.NAME + "/" + "a" * 32,
            "kid": merge.BASE + "/keys/" + merge.NAME + "/" + "a" * 32,
            "sid": merge.BASE + "/secrets/" + merge.NAME + "/" + "a" * 32,
            "cer": base64.b64encode(der).decode(), "attributes": {"enabled": True, "exp": EXPIRY}, **overrides}


class ServerMergeTests(unittest.TestCase):
    def run_scenario(self, responses, identity=None, ip="10.20.5.22", fingerprint_value=None):
        with patch.dict(merge.os.environ, {"AZURE_CLIENT_ID": identity or merge.IDENTITY}), \
             patch.object(merge.socket, "getaddrinfo", return_value=[(None, None, None, None, (ip, 443))]), \
             patch.object(merge, "public_material", return_value=([b"leaf", b"intermediate", b"cross-sign"], EXPIRY)), \
             patch.object(merge, "acquire_token", return_value="test-only"), \
             patch.object(merge, "fingerprint", side_effect=lambda der: fingerprint_value or (merge.EXPECTED_CSR if der == b"csr" else merge.CHAIN_SHA256[0])), \
             patch.object(merge, "request", side_effect=responses) as request, \
             contextlib.redirect_stdout(io.StringIO()):
            merge.main()
            return request.call_args_list

    def test_successful_merge_is_bounded_and_never_reads_secrets(self):
        calls = self.run_scenario([(404, {}), (200, {"csr": base64.b64encode(b"csr").decode()}), (200, bundle()), (200, bundle())])
        self.assertEqual(sum(c.args[0] == "POST" for c in calls), 1)
        self.assertTrue(all("/certificates/" in c.args[1] for c in calls))
        self.assertEqual(len(calls[2].args[2]["x5c"]), 3)

    def test_matching_existing_certificate_is_read_only(self):
        calls = self.run_scenario([(200, bundle())])
        self.assertTrue(all(c.args[0] == "GET" for c in calls))

    def test_existing_unexpected_certificate_rejected(self):
        with self.assertRaises(merge.SafeFailure):
            self.run_scenario([(200, bundle())], fingerprint_value="different")

    def test_wrong_pending_csr_rejected(self):
        with self.assertRaises(merge.SafeFailure):
            self.run_scenario([(404, {}), (200, {"csr": base64.b64encode(b"wrong").decode()})])

    def test_permission_denial_does_not_retry(self):
        with self.assertRaises(merge.SafeFailure):
            self.run_scenario([(403, {})])

    def test_merge_failure_does_not_retry(self):
        with self.assertRaises(merge.SafeFailure):
            self.run_scenario([(404, {}), (200, {"csr": base64.b64encode(b"csr").decode()}), (500, {})])

    def test_disabled_certificate_rejected(self):
        with self.assertRaises(merge.SafeFailure):
            self.run_scenario([(200, bundle(attributes={"enabled": False, "exp": EXPIRY}))])

    def test_wrong_identity_rejected(self):
        with self.assertRaises(merge.SafeFailure):
            self.run_scenario([], identity="other")

    def test_public_vault_dns_rejected(self):
        with self.assertRaises(merge.SafeFailure):
            self.run_scenario([], ip="203.0.113.1")

    def test_real_reviewed_public_chain_passes(self):
        public = ROOT.parent.parent / ".azure" / "pki" / "acme-issued-public-production"
        if not (public / "public-verification.json").is_file() or not (public / "server-chain.pem").is_file():
            self.skipTest("Public certificate fixtures are not included in the repository")
        with patch("builtins.open", side_effect=lambda name, **kwargs: (public / ("public-verification.json" if pathlib.Path(name).name == "server-verification.json" else pathlib.Path(name).name)).open(**kwargs)):
            chain, expiry = merge.public_material()
        self.assertEqual(len(chain), 3)
        self.assertEqual(expiry, EXPIRY)


if __name__ == "__main__":
    unittest.main()
