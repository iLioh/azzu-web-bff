# PKI source handoff — not deployment approval

These sources document the completed DEV CSR/certificate workflow. No certificate, private key, DPAPI state or kubeconfig is included. Current versions/fingerprints and the verified image digest live in [azzu-cloud-infra README](https://github.com/iLioh/azzu-cloud-infra#readme).

## Tool boundaries

- `Test-OidcLoginPreflight.ps1` (parent directory): read-only Graph/discovery, never successful login evidence.
- `New-MappingClientCsr.ps1`: default preview; `-CreatePendingRequest` creates a KV object after private DNS/existence gates. Mapping cert already exists; do not rerun blindly.
- `Start-*.ps1`: explicit authorized `-Kubeconfig`; server dry-run by default, `-Execute` creates namespace-scoped Jobs/ConfigMaps/policies. This is NOT an offline preview and may invoke admission webhooks. They do not deploy the BFF server. Existing names/template Jobs/selectors/cert pins are historical snapshots and fail if missing/different.
- `create-*.py` and `merge-*.py`: executable Job payloads that can WRITE certificates when launched. Reuse original KV key, strict private DNS, no secret/key download, no automatic broad permission fixes. Invocation itself needs approval; publishing the source is not approval.
- `Prepare-ManualAcme.mjs` / `Complete-ManualAcme.mjs`: explicit execution gates; create account/order or finalize an existing order. Direct TXT DNS-01, no DNS writes, no public backend A. Windows CurrentUser DPAPI local state is NOT portable to Aldo/Linux; never commit or send the protected account key by chat. Plan a separately protected operator account for renewal, not a silent attempt to reuse another user's state.
- `Protect-AcmeAccount.ps1` is a stdin/stdout IPC helper for Node. `Unprotect` returns plaintext to its authorized parent process: never invoke it interactively or capture output/transcripts in logs.
- Public CA/cert/CSR material and Key Vault private access must be obtained through the authorized channel. Tools may use Windows Git OpenSSL paths. No PFX or private key should be copied to a PC to make them work.
- Bootstrap namespace/default-deny and the CSR provisioning Bicep describe already completed work, not scripts to reapply to a shared cluster. All writes require fresh diff/approval.

Mapping probe takes `-FixtureOid` and `-ExpectedCustomerId` supplied explicitly for an approved DEV fixture. They are diagnostic expectations, not a way to authorize a customer or bypass validated sessions. Do not print them. Probe env values are visible to authorized Kubernetes workload readers; use synthetic fixtures only.

## Offline tests (no Azure mutation)

```powershell
node --test scripts/pki/Prepare-ManualAcme.test.mjs scripts/pki/Complete-ManualAcme.test.mjs
python -B -m unittest discover -s scripts/pki -p 'test_server_*.py'
dotnet build tools/Azzu.MappingProbe/Azzu.MappingProbe.csproj -c Release
dotnet build tools/Azzu.OidcProbe/Azzu.OidcProbe.csproj -c Release
```

The merge suite contains one real PUBLIC chain check requiring ignored local files under `.azure/pki/acme-issued-public-production`; absence is explicitly reported as SKIP, not PASS. Unit mocks do not prove live TLS, certificate allowlisting or OIDC user authentication. Do not execute operational entrypoints as tests.
