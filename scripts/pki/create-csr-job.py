"""One-shot Key Vault CSR creation. Emits public CSR only; never reads keys/secrets.

Uses projected AKS Workload Identity token, OAuth client assertion and verified HTTPS.
No client secret, Kubernetes API access, database access or private-key export.
"""
import base64
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VAULT_HOST = "kv-azzu-web-dev-8466fe.vault.azure.net"
CERT_NAME = "azzu-web-bff-dev-mapping-mtls"
TENANT = "9163187e-371b-4d3c-b5dd-f20f1b182fa7"
BASE = "https://" + VAULT_HOST
TLS = ssl.create_default_context()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a bearer token or client assertion to a redirected endpoint.
        return None


HTTP = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=TLS))


class SafeFailure(Exception):
    pass


def request(method, url, payload=None, token=None, form=False):
    headers = {"Accept": "application/json"}
    data = None
    if payload is not None:
        data = (urllib.parse.urlencode(payload) if form else json.dumps(payload)).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with HTTP.open(req, timeout=25) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        # Do not emit response bodies, tokens, assertions, or exception URLs.
        return error.code, {}


def acquire_token():
    if os.environ.get("AZURE_TENANT_ID") != TENANT:
        raise SafeFailure("Unexpected Workload Identity tenant")
    with open(os.environ["AZURE_FEDERATED_TOKEN_FILE"], encoding="utf-8") as stream:
        assertion = stream.read().strip()
    status, response = request("POST", f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token", {
        "client_id": os.environ["AZURE_CLIENT_ID"],
        "grant_type": "client_credentials",
        "scope": "https://vault.azure.net/.default",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }, form=True)
    if status != 200 or not response.get("access_token"):
        raise SafeFailure(f"Workload Identity token exchange failed: HTTP {status}")
    return response["access_token"]


def main():
    addresses = {item[4][0] for item in socket.getaddrinfo(VAULT_HOST, 443, family=socket.AF_INET)}
    if addresses != {"10.20.5.22"}:
        raise SafeFailure("Private DNS gate failed; certificate creation not attempted")
    print("PRIVATE_DNS_PASS:10.20.5.22", flush=True)
    token = acquire_token()
    # Wait only for RBAC propagation; never broaden roles or retry a certificate creation.
    for attempt in range(12):
        status, _ = request("GET", BASE + "/certificates?api-version=7.4&maxresults=1", token=token)
        if status == 200:
            break
        if status != 403 or attempt == 11:
            raise SafeFailure(f"Certificate permission gate failed: HTTP {status}")
        time.sleep(15)
    print("CERTIFICATE_PERMISSION_PASS", flush=True)
    for path in (f"/certificates/{CERT_NAME}", f"/certificates/{CERT_NAME}/pending", f"/deletedcertificates/{CERT_NAME}"):
        status, _ = request("GET", BASE + path + "?api-version=7.4", token=token)
        if status != 404:
            raise SafeFailure(f"Refusing overwrite: certificate existence gate returned HTTP {status}")
    policy = {
        "issuer": {"name": "Unknown"},
        "key_props": {"exportable": True, "key_size": 3072, "kty": "RSA", "reuse_key": False},
        "secret_props": {"contentType": "application/x-pkcs12"},
        "x509_props": {"subject": "CN=azzu-web-bff-dev", "ekus": ["1.3.6.1.5.5.7.3.2"],
                       "key_usage": ["digitalSignature"], "validity_months": 1},
        "lifetime_actions": [],
    }
    status, response = request("POST", BASE + f"/certificates/{CERT_NAME}/create?api-version=7.4",
                               {"policy": policy}, token=token)
    if status not in (200, 202):
        raise SafeFailure(f"Create certificate request failed: HTTP {status}; do not retry blindly")
    for _ in range(12):
        if response.get("csr"):
            csr = base64.urlsafe_b64decode(response["csr"] + "=" * (-len(response["csr"]) % 4))
            print("PUBLIC_CSR_DER_BASE64:" + base64.b64encode(csr).decode(), flush=True)
            print("CSR_READY_PENDING_EXTERNAL_SIGNATURE", flush=True)
            return
        time.sleep(5)
        status, response = request("GET", BASE + f"/certificates/{CERT_NAME}/pending?api-version=7.4", token=token)
        if status != 200:
            raise SafeFailure(f"Pending certificate read failed: HTTP {status}")
    raise SafeFailure("CSR not yet available; inspect pending certificate, do not recreate")


if __name__ == "__main__":
    try:
        main()
    except SafeFailure as error:
        print("SAFE_FAILURE:" + str(error), flush=True)
        sys.exit(1)
    except Exception as error:
        print("SAFE_FAILURE:" + type(error).__name__ + "; inspect phase, no automatic mutation retry", flush=True)
        sys.exit(1)
