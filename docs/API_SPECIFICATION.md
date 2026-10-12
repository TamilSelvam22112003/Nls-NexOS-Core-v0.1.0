# API Specification (v1)

Base path: `/api/v1`

## `GET /health`

Returns service readiness. It contains no secret or trust assertion; TLS certificate validation is still required.

## `POST /enroll`

Initial bootstrap endpoint. Requires pinned server TLS trust and a configured high-entropy enrollment token. Request JSON includes:
- `protocol_version`
- `router_id`
- `csr_pem`
- `request_id`
- `nonce`
- `timestamp`
- optional claimed network metadata

The response returns `certificate_pem`, `ca_certificate_pem`, `serial_number`, `not_before`, `not_after`, and `router_id`. The API must never return private-key material.

The prototype uses the enrollment token in an HTTP header. Deploy only over verified TLS; rotate/delete the bootstrap token after successful enrollment. Production should support one-time tokens and an administrator-operated provisioning workflow.

## `GET /api/v1/policy`

Requires a valid client certificate after enrollment; returns versioned policy.

## `GET /api/v1/revocation`

Requires client certificate; returns current revocation material/status.

## TLS

The sample implementation exposes enrollment through HTTPS when configured with a TLS certificate. A production deployment should terminate TLS only in a trusted process and pass a validated client-certificate identity to the application for policy endpoints.
