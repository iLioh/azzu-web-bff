"""One-shot merge of the reviewed public server chain; no key/secret downloads."""
import base64
import datetime
import hashlib
import json
import os
import re
import socket
import ssl
import sys
from create_csr_job import BASE, VAULT_HOST, SafeFailure, acquire_token, request

NAME = "azzu-web-bff-dev-server-tls"
HOSTNAME = "web-bff.internal.azzu.tech"
IDENTITY = "02fc8537-31b3-41b5-a6a8-68f2ba4c0bb9"
EXPECTED_CSR = "8300E52FB43B15D5BCB79E11C09AB104AEBCE766137F3C4CC0FB36CBD61BECA8"
CHAIN_SHA256 = [
    "5611F420661D5CC6CC545E9FDEB6BF8A4AEC6B6A7BCF8BA6EBD6234191FCC6A3",
    "238B85A0099C65B970477D5724F1A1D475CE5058CFFE4EFA8733899BDB863C47",
    "072639D0B140D5BFFAE16AD9C3F6CC6086040621F51EE61A6D46A8915C07CF76",
]


def fingerprint(der):
    return hashlib.sha256(der).hexdigest().upper()


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def public_material():
    with open("/code/server-verification.json", encoding="utf-8") as stream:
        verification = json.load(stream)
    with open("/code/server-chain.pem", encoding="ascii") as stream:
        pem = stream.read()
    if ("PRIVATE KEY" in pem or len(pem) > 131072 or verification.get("hostname") != HOSTNAME
            or verification.get("certificateName") != NAME or verification.get("csrSha256") != EXPECTED_CSR
            or verification.get("certificateSha256") != CHAIN_SHA256[0]
            or verification.get("chainSha256") != CHAIN_SHA256
            or verification.get("systemTrustVerified") is not True):
        raise SafeFailure("Reviewed public material metadata gate failed")
    parts = re.findall(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", pem)
    if len(parts) != len(CHAIN_SHA256) or re.sub(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", "", pem).strip():
        raise SafeFailure("Public chain structure gate failed")
    chain = [ssl.PEM_cert_to_DER_cert(part) for part in parts]
    if [fingerprint(der) for der in chain] != CHAIN_SHA256:
        raise SafeFailure("Public chain fingerprint gate failed")
    expiry = int(datetime.datetime.fromisoformat(verification["notAfter"].replace("Z", "+00:00")).timestamp())
    if expiry <= int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 7 * 86400:
        raise SafeFailure("Certificate expires too soon; no merge")
    return chain, expiry


def verified_result(result, expiry):
    if (not result.get("cer") or fingerprint(decode(result["cer"])) != CHAIN_SHA256[0]
            or result.get("attributes", {}).get("enabled") is not True
            or result.get("attributes", {}).get("exp") != expiry
            or not re.fullmatch(re.escape(BASE + "/certificates/" + NAME + "/") + r"[a-f0-9]{32}", result.get("id", ""))
            or not result.get("kid", "").startswith(BASE + "/keys/" + NAME + "/")
            or not result.get("sid", "").startswith(BASE + "/secrets/" + NAME + "/")):
        raise SafeFailure("Post-merge public certificate metadata gate failed")
    print(json.dumps({"certificateId": result["id"], "keyId": result["kid"],
                      "enabled": True, "expiresUnix": expiry, "certificateSha256": CHAIN_SHA256[0]}), flush=True)


def main():
    if os.environ.get("AZURE_CLIENT_ID") != IDENTITY:
        raise SafeFailure("Unexpected provisioning identity")
    addresses = {item[4][0] for item in socket.getaddrinfo(VAULT_HOST, 443, family=socket.AF_INET)}
    if addresses != {"10.20.5.22"}:
        raise SafeFailure("Private vault DNS gate failed")
    print("PRIVATE_VAULT_DNS_PASS", flush=True)
    chain, expiry = public_material()
    print("REVIEWED_PUBLIC_SERVER_CHAIN_PASS", flush=True)
    token = acquire_token()
    path = BASE + "/certificates/" + NAME
    status, existing = request("GET", path + "?api-version=7.4", token=token)
    if status == 200 and existing.get("cer"):
        verified_result(existing, expiry)
        print("ALREADY_MERGED_EXPECTED_SERVER_CERTIFICATE", flush=True)
        return
    if status not in (200, 404):
        raise SafeFailure(f"Existing certificate gate HTTP {status}; no mutation")
    original_key = existing.get("kid")
    status, pending = request("GET", path + "/pending?api-version=7.4", token=token)
    if status != 200 or not pending.get("csr") or fingerprint(decode(pending["csr"])) != EXPECTED_CSR:
        raise SafeFailure("Pending server CSR does not match reviewed signed CSR; no merge")
    print("PENDING_SERVER_CSR_EXACT_MATCH_PASS", flush=True)
    status, merged = request("POST", path + "/pending/merge?api-version=7.4",
                             {"x5c": [base64.b64encode(der).decode() for der in chain]}, token=token)
    if status not in (200, 201):
        raise SafeFailure(f"Server merge HTTP {status}; no recreate or blind retry")
    if original_key and merged.get("kid") != original_key:
        raise SafeFailure("Unexpected keyId change; inspect, do not retry")
    verified_result(merged, expiry)
    status, verified = request("GET", path + "?api-version=7.4", token=token)
    if status != 200 or verified.get("id") != merged.get("id"):
        raise SafeFailure("Post-merge version read gate failed")
    verified_result(verified, expiry)
    print("SERVER_MERGE_AND_PUBLIC_READBACK_PASS", flush=True)


if __name__ == "__main__":
    try:
        main()
    except SafeFailure as error:
        print("SAFE_FAILURE:" + str(error), flush=True)
        sys.exit(1)
    except Exception as error:
        print("SAFE_FAILURE:" + type(error).__name__ + "; no automatic retry", flush=True)
        sys.exit(1)
