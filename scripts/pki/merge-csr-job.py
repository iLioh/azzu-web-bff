"""Merge validated public signed chain into an existing Key Vault pending CSR.

Never calls /keys or /secrets, creates another key, or disables TLS verification.
"""
import base64
import hashlib
import importlib.util
import json
import os
import socket
import ssl
import sys

spec = importlib.util.spec_from_file_location("csr_auth", "/code/create-csr-job.py")
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)

EXPECTED_CSR = "83771D336BD0A0E6BF6236AA540F311E2660558D57C4A2ABB2E54CF82E7252DC"
EXPECTED_CERT = "05204949158241B2181C4409A9E77F8D7EA75E6F6446A0A4083755465AD410A0"
EXPECTED_CA = "A39C981E537F60D62EF541960183A397B320A4D71877D05D2E04E38F8115D78E"


def fingerprint(der):
    return hashlib.sha256(der).hexdigest().upper()


def decode_url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def main():
    addresses = {row[4][0] for row in socket.getaddrinfo(auth.VAULT_HOST, 443, family=socket.AF_INET)}
    if addresses != {"10.20.5.22"}:
        raise auth.SafeFailure("Private DNS gate failed")
    print("PRIVATE_DNS_PASS:10.20.5.22", flush=True)
    with open("/code/client.crt.pem", encoding="ascii") as stream:
        cert = ssl.PEM_cert_to_DER_cert(stream.read())
    with open("/code/ca.crt", encoding="ascii") as stream:
        ca = ssl.PEM_cert_to_DER_cert(stream.read())
    if fingerprint(cert) != EXPECTED_CERT or fingerprint(ca) != EXPECTED_CA:
        raise auth.SafeFailure("Public certificate fingerprint gate failed")
    token = auth.acquire_token()
    print("WORKLOAD_IDENTITY_PASS", flush=True)
    path = auth.BASE + "/certificates/" + auth.CERT_NAME
    status, existing = auth.request("GET", path + "?api-version=7.4", token=token)
    if status == 200 and existing.get("cer"):
        if fingerprint(decode_url(existing["cer"])) != EXPECTED_CERT:
            raise auth.SafeFailure("An unexpected certificate already exists; refusing mutation")
        print("ALREADY_MERGED_EXPECTED_CERTIFICATE", flush=True)
        return
    if status not in (200, 404):
        raise auth.SafeFailure(f"Existing certificate gate failed: HTTP {status}")
    original_key_id = existing.get("kid")
    print("EXISTING_CERTIFICATE_STATUS:" + str(status) + "; signedCer=" + str(bool(existing.get("cer"))), flush=True)
    status, pending = auth.request("GET", path + "/pending?api-version=7.4", token=token)
    if status != 200 or not pending.get("csr"):
        raise auth.SafeFailure(f"Pending request gate failed: HTTP {status}")
    if fingerprint(decode_url(pending["csr"])) != EXPECTED_CSR:
        raise auth.SafeFailure("Pending CSR differs from the signed original; refusing merge")
    print("PENDING_CSR_MATCH_PASS", flush=True)
    if os.environ.get("MERGE_INSPECT_ONLY") == "true":
        print("MERGE_INSPECTION_PASS_NO_MUTATION", flush=True)
        return
    chain = [base64.b64encode(cert).decode(), base64.b64encode(ca).decode()]
    status, merged = auth.request("POST", path + "/pending/merge?api-version=7.4", {"x5c": chain}, token=token)
    if status not in (200, 201):
        raise auth.SafeFailure(f"Merge failed: HTTP {status}; no recreate or blind retry")
    if fingerprint(decode_url(merged["cer"])) != EXPECTED_CERT:
        raise auth.SafeFailure("Merged certificate fingerprint mismatch")
    if original_key_id and merged.get("kid") != original_key_id:
        raise auth.SafeFailure("Unexpected keyId change during merge")
    status, verified = auth.request("GET", path + "?api-version=7.4", token=token)
    if status != 200 or fingerprint(decode_url(verified["cer"])) != EXPECTED_CERT:
        raise auth.SafeFailure("Post-merge certificate read verification failed")
    print("MERGE_SIGNED_REQUEST_PASS", flush=True)
    print(json.dumps({"certificateId": verified["id"], "keyId": verified.get("kid"),
                      "enabled": verified.get("attributes", {}).get("enabled"),
                      "expiresUnix": verified.get("attributes", {}).get("exp"),
                      "certificateSha256": EXPECTED_CERT}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except auth.SafeFailure as error:
        print("SAFE_FAILURE:" + str(error), flush=True)
        sys.exit(1)
    except Exception as error:
        print("SAFE_FAILURE:" + type(error).__name__ + "; inspect pending operation, do not recreate", flush=True)
        sys.exit(1)
