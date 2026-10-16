import pytest
from pydantic import ValidationError
from nls_nexos_core.models import EnrollmentRequest

def sample(**change):
    value=dict(protocol_version=1,router_id='edge-1',csr_pem='x'*150,request_id='r'*24,nonce='n'*32,timestamp=1000,rsa_encryption_public_key='p'*150,rsa_proof_of_possession='s'*100)
    value.update(change)
    return value

def test_valid_model(): assert EnrollmentRequest(**sample()).router_id=='edge-1'
def test_extra_field_rejected():
    with pytest.raises(ValidationError): EnrollmentRequest(**sample(extra='no'))
def test_bad_router_id_rejected():
    with pytest.raises(ValidationError): EnrollmentRequest(**sample(router_id='../bad'))
def test_short_request_id_rejected():
    with pytest.raises(ValidationError): EnrollmentRequest(**sample(request_id='short'))


def test_router_cannot_supply_operator_directory_metadata():
    with pytest.raises(ValidationError):
        EnrollmentRequest(**sample(wan_endpoints=["198.51.100.1:4789"]))
