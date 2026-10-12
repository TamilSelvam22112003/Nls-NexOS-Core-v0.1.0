from datetime import datetime,timedelta,timezone
from ipaddress import IPv6Address
import hashlib,re,secrets,time
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from .database import Registry
from .models import EnrollmentRequest,EnrollmentResponse
class EnrollmentDenied(Exception):pass
class CertificateAuthority:
 def __init__(self,settings,registry:Registry,token):
  self.settings,self.registry,self.token=settings,registry,token
  self.ca_cert=x509.load_pem_x509_certificate(settings.ca_certificate.read_bytes()); self.ca_key=serialization.load_pem_private_key(settings.ca_private_key.read_bytes(),password=None)
  if not isinstance(self.ca_key,rsa.RSAPrivateKey) or self.ca_key.key_size<3072:raise RuntimeError('CA key must be RSA >=3072 bits')
  if self.ca_cert.public_key().public_numbers()!=self.ca_key.public_key().public_numbers():raise RuntimeError('CA key/certificate mismatch')
 def enroll(self,req:EnrollmentRequest,presented_token:str)->EnrollmentResponse:
  now_epoch=int(time.time()); now=datetime.now(timezone.utc)
  if not secrets.compare_digest(self.token,presented_token): self.registry.audit('ENROLL_DENIED',req.router_id,'invalid credential',now_epoch); raise EnrollmentDenied()
  if abs(now_epoch-req.timestamp)>300 or not re.fullmatch(r'[A-Za-z0-9_-]{32,128}',req.nonce):raise EnrollmentDenied()
  try:csr=x509.load_pem_x509_csr(req.csr_pem.encode())
  except (ValueError,TypeError) as exc:raise EnrollmentDenied() from exc
  if not csr.is_signature_valid:raise EnrollmentDenied()
  router=self.registry.get_router(req.router_id)
  if not router or not router['registered'] or router['status']!='ACTIVE':self.registry.audit('ENROLL_DENIED',req.router_id,'router not registered/active',now_epoch); raise EnrollmentDenied()
  pub=csr.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo); fingerprint=hashlib.sha256(pub).hexdigest(); expected=router.get('expected_public_key_sha256')
  if expected and not secrets.compare_digest(expected.lower(),fingerprint):raise EnrollmentDenied()
  if req.claimed_ipv6:
   try:IPv6Address(req.claimed_ipv6)
   except ValueError as exc:raise EnrollmentDenied() from exc
   if router.get('allowed_ipv6') and req.claimed_ipv6!=router['allowed_ipv6']:raise EnrollmentDenied()
  if req.claimed_mac and (not re.fullmatch(r'(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}',req.claimed_mac) or (router.get('allowed_mac') and req.claimed_mac.lower()!=router['allowed_mac'].lower())):raise EnrollmentDenied()
  if not self.registry.is_request_new(req.request_id,req.router_id,hashlib.sha256(req.nonce.encode()).hexdigest(),now_epoch):raise EnrollmentDenied()
  before,after=now-timedelta(minutes=2),now+timedelta(days=self.settings.certificate_days); subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,req.router_id)])
  cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(self.ca_cert.subject).public_key(csr.public_key()).serial_number(x509.random_serial_number()).not_valid_before(before.replace(tzinfo=None)).not_valid_after(after.replace(tzinfo=None)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=None,decipher_only=None),critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False).add_extension(x509.SubjectAlternativeName([x509.DNSName(req.router_id)]),critical=False).sign(self.ca_key,hashes.SHA256()))
  pem=cert.public_bytes(serialization.Encoding.PEM).decode('ascii'); serial=format(cert.serial_number,'x'); before_s,after_s=before.isoformat(),after.isoformat(); digest=hashlib.sha256(pem.encode()).hexdigest(); self.settings.issued_cert_dir.mkdir(parents=True,exist_ok=True); target=self.settings.issued_cert_dir/f'{serial}.crt'; tmp=target.with_suffix('.tmp'); tmp.write_text(pem,encoding='ascii'); tmp.chmod(0o640); tmp.replace(target)
  self.registry.record_certificate(serial,req.router_id,before_s,after_s,digest,now_epoch); self.registry.audit('CERT_ISSUED',req.router_id,'serial='+serial,now_epoch)
  return EnrollmentResponse(router_id=req.router_id,serial_number=serial,certificate_pem=pem,ca_certificate_pem=self.ca_cert.public_bytes(serialization.Encoding.PEM).decode('ascii'),not_before=before_s,not_after=after_s)