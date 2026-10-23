# DocuSeal automated signing API

A narrow, independent API around the public DocuSeal PDF signing implementation.
It does not expose the Pro PDF submission endpoints. It signs a PDF invisibly with
an operator-provided service certificate and records the application's responsible
person in a separately signed audit PDF. This is not a personal signing ceremony,
a QES, an externally validated person certificate, or a trusted timestamp.

Attribution: **Powered by DocuSeal**. AGPL-3.0 and LICENSE_ADDITIONAL_TERMS apply.
Full corresponding source is linked in every response and at `/source`.
The normal DocuSeal Rails application/UI is not exposed in this service deployment.

## Deployment

Build `signing_api/Dockerfile` from the repository root. For Fly, run
`fly deploy . --remote-only --ha=false --config fly.signing.toml` from that root.
Mount durable storage at
`/data/docuseal/signing` owned by uid 2000. Run one machine for this volume (no
independent replicas). Provider volume snapshots and an operator backup are
required. The calling application additionally archives original, signed file,
and audit PDF. Restore the volume before reusing operation IDs on a new machine.

Secrets (never commit values): `SIGNING_API_TOKEN` (32+ random bytes),
`SIGNING_KEY_PEM`, `SIGNING_CERT_PEM`, `SIGNING_IDENTITIES_JSON` (object keyed by
user UUID, containing tenant_id, name, email, authority_ref). Certificate must be
valid, match key, and accurately identify the service. Configure authenticated
clients with the certificate SHA256 fingerprint. Rotate keys deliberately;
retain old certificate/evidence and reconfigure clients before signing new jobs.

`POST /operations/{uuid}` accepts JSON with `pdf` (base64), `original_sha256`,
`tenant_id`, `document_id`, `signer_id`, `signer_name`, `signer_email`,
`assignment_sha256`, `authority_ref`. Bearer authentication is mandatory.
The PDF must be unsigned and unencrypted. At most 25 MB / 100 pages.
`GET /operations/{uuid}` retrieves the durable result with the same authentication.
Same operation and input returns the same bytes. Different input returns 409.
Timeouts must reconcile using GET; same-key POST is idempotent on the same volume.

No SMTP, invitation, notification or webhook delivery runs in this API. No user
registration, generic upload route, shell execution, or remote URL download exists.
The service is trusted infrastructure; it does not prove personal consent or the
truth of assignment data supplied by its authenticated, allowlisted client.
