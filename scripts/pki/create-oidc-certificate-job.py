"""Approved one-shot OIDC certificate issuance; public output only, no secret read."""
import base64
import hashlib
import os
import socket
import sys
import time
from create_csr_job import BASE, VAULT_HOST, SafeFailure, acquire_token, request

NAME = "azzu-web-bff-dev-oidc"
EXPECTED_IDENTITY = "02fc8537-31b3-41b5-a6a8-68f2ba4c0bb9"


def main():
    if os.environ.get("AZURE_CLIENT_ID") != EXPECTED_IDENTITY:
        raise SafeFailure("Unexpected provisioning identity")
    addresses = {item[4][0] for item in socket.getaddrinfo(VAULT_HOST, 443, family=socket.AF_INET)}
    if addresses != {"10.20.5.22"}:
        raise SafeFailure("Private vault DNS gate failed")
    print("PRIVATE_VAULT_DNS_PASS", flush=True)
    token = acquire_token()
    print("PROVISIONING_WORKLOAD_IDENTITY_PASS", flush=True)
    for path in (f"/certificates/{NAME}", f"/certificates/{NAME}/pending", f"/deletedcertificates/{NAME}"):
        status, _ = request("GET", BASE + path + "?api-version=7.4", token=token)
        if status != 404:
            raise SafeFailure(f"No-overwrite gate: HTTP {status}; inspect existing certificate, no retry")
    policy = {
        "issuer": {"name": "Self"},
        "key_props": {"exportable": True, "key_size": 3072, "kty": "RSA", "reuse_key": False},
        "secret_props": {"contentType": "application/x-pkcs12"},
        "x509_props": {"subject": "CN=azzu-web-bff-dev-oidc", "key_usage": ["digitalSignature"], "validity_months": 3},
        "lifetime_actions": [],
    }
    status, _ = request("POST", BASE + f"/certificates/{NAME}/create?api-version=7.4", {"policy": policy}, token=token)
    if status not in (200, 202):
        raise SafeFailure(f"OIDC certificate creation HTTP {status}; do not retry blindly")
    for _ in range(20):
        status, result = request("GET", BASE + f"/certificates/{NAME}?api-version=7.4", token=token)
        if status == 200 and result.get("cer"):
            public_der = base64.urlsafe_b64decode(result["cer"] + "=" * (-len(result["cer"]) % 4))
            print("PUBLIC_CERT_DER_BASE64:" + base64.b64encode(public_der).decode(), flush=True)
            print("OIDC_CERTIFICATE_ID:" + result["id"], flush=True)
            print("OIDC_CERTIFICATE_SHA256:" + hashlib.sha256(public_der).hexdigest().upper(), flush=True)
            print("OIDC_CERTIFICATE_CREATED_PASS", flush=True)
            return
        if status not in (200, 404):
            raise SafeFailure(f"Certificate completion read HTTP {status}")
        time.sleep(3)
    raise SafeFailure("Creation not completed; inspect pending, never re-create automatically")


if __name__ == "__main__":
    try:
        main()
    except SafeFailure as error:
        print("SAFE_FAILURE:" + str(error), flush=True)
        sys.exit(1)
    except Exception as error:
        print("SAFE_FAILURE:" + type(error).__name__ + "; no automatic mutation retry", flush=True)
        sys.exit(1)
