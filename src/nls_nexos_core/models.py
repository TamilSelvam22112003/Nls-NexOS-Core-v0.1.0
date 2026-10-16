from pydantic import BaseModel, ConfigDict, Field

class EnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol_version: int = Field(ge=1, le=1)
    router_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    csr_pem: str = Field(min_length=100, max_length=50000)
    request_id: str = Field(min_length=16, max_length=128)
    nonce: str = Field(min_length=32, max_length=128)
    timestamp: int = Field(ge=0)
    rsa_encryption_public_key: str = Field(min_length=100, max_length=20000)
    rsa_proof_of_possession: str = Field(min_length=80, max_length=4096)
    claimed_ipv6: str | None = Field(default=None, max_length=64)
    claimed_mac: str | None = Field(default=None, max_length=32)

class EnrollmentResponse(BaseModel):
    protocol_version: int = 1
    router_id: str
    serial_number: str
    certificate_pem: str
    ca_certificate_pem: str
    not_before: str
    not_after: str

class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "nls-router-ca"
    protocol_version: int = 1
