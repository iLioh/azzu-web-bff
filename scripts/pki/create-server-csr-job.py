"""Create/reuse only the server CSR. No keys/secrets are downloaded."""
import base64
import hashlib
import os
import socket
import sys
import time
from create_csr_job import BASE, VAULT_HOST, SafeFailure, acquire_token, request

NAME = "azzu-web-bff-dev-server-tls"
HOSTNAME = "web-bff.internal.azzu.tech"
IDENTITY = "02fc8537-31b3-41b5-a6a8-68f2ba4c0bb9"


def main():
    if os.environ.get("AZURE_CLIENT_ID") != IDENTITY:
        raise SafeFailure("Unexpected provisioning identity")
    addresses = {i[4][0] for i in socket.getaddrinfo(VAULT_HOST, 443, family=socket.AF_INET)}
    if addresses != {"10.20.5.22"}:
        raise SafeFailure("Private vault DNS gate failed")
    print("PRIVATE_VAULT_DNS_PASS", flush=True)
    token = acquire_token()
    status, _ = request("GET", BASE + f"/certificates/{NAME}?api-version=7.4", token=token)
    if status != 404:
        raise SafeFailure(f"Existing certificate/permission gate HTTP {status}; no overwrite")
    status, pending = request("GET", BASE + f"/certificates/{NAME}/pending?api-version=7.4", token=token)
    if status == 200:
        policy_status, policy = request("GET", BASE + f"/certificates/{NAME}/policy?api-version=7.4", token=token)
        x509 = policy.get("x509_props", {})
        if (policy_status != 200 or policy.get("issuer", {}).get("name") != "Unknown"
                or x509.get("sans", {}).get("dns_names") != [HOSTNAME]
                or x509.get("subject") != "CN=" + HOSTNAME
                or x509.get("ekus") != ["1.3.6.1.5.5.7.3.1"]
                or policy.get("key_props", {}).get("kty") != "RSA"
                or policy.get("key_props", {}).get("key_size", 0) < 3072):
            raise SafeFailure("Existing pending policy mismatch; no mutation")
        print("EXISTING_PENDING_SERVER_CSR_REUSED", flush=True)
    elif status == 404:
        deleted_status, _ = request("GET", BASE + f"/deletedcertificates/{NAME}?api-version=7.4", token=token)
        if deleted_status != 404:
            raise SafeFailure(f"Deleted certificate gate HTTP {deleted_status}; no overwrite")
        policy = {
            "issuer": {"name": "Unknown"},
            # TLS uses the backing PFX only inside the authorized runtime later.
            "key_props": {"exportable": True, "key_size": 3072, "kty": "RSA", "reuse_key": False},
            "secret_props": {"contentType": "application/x-pkcs12"},
            "x509_props": {"subject": "CN=" + HOSTNAME, "sans": {"dns_names": [HOSTNAME]},
                           "ekus": ["1.3.6.1.5.5.7.3.1"], "key_usage": ["digitalSignature", "keyEncipherment"],
                           "validity_months": 3},
            "lifetime_actions": [],
        }
        status, pending = request("POST", BASE + f"/certificates/{NAME}/create?api-version=7.4", {"policy": policy}, token=token)
        if status not in (200, 202):
            raise SafeFailure(f"Server CSR create HTTP {status}; no blind retry")
        print("SERVER_CSR_CREATED_IN_PRIVATE_VAULT", flush=True)
    else:
        raise SafeFailure(f"Pending read HTTP {status}; no mutation")
    for _ in range(15):
        if pending.get("csr"):
            der = base64.urlsafe_b64decode(pending["csr"] + "=" * (-len(pending["csr"]) % 4))
            print("PUBLIC_SERVER_CSR_DER_BASE64:" + base64.b64encode(der).decode(), flush=True)
            print("PUBLIC_SERVER_CSR_SHA256:" + hashlib.sha256(der).hexdigest().upper(), flush=True)
            print("SERVER_CSR_PENDING_ACME_SIGNATURE", flush=True)
            return
        time.sleep(3)
        status, pending = request("GET", BASE + f"/certificates/{NAME}/pending?api-version=7.4", token=token)
        if status != 200:
            raise SafeFailure(f"Pending CSR read HTTP {status}; no recreate")
    raise SafeFailure("CSR not available yet; inspect pending operation")


if __name__ == "__main__":
    try:
        main()
    except SafeFailure as error:
        print("SAFE_FAILURE:" + str(error), flush=True)
        sys.exit(1)
    except Exception as error:
        print("SAFE_FAILURE:" + type(error).__name__ + "; no automatic retry", flush=True)
        sys.exit(1)
