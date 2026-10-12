import pytest
from pydantic import ValidationError
from nls_nexos_core.models import EnrollmentRequest

def test_required_fields():
    with pytest.raises(ValidationError): EnrollmentRequest(protocol_version=1,router_id='r1',csr_pem='x'*150)
def test_protocol_version():
    with pytest.raises(ValidationError): EnrollmentRequest(protocol_version=2,router_id='r1',csr_pem='x'*150,request_id='r'*24,nonce='n'*32,timestamp=123)
