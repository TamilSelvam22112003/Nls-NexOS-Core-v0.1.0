import argparse,hashlib,os,secrets,time
from datetime import datetime,timedelta,timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from .config import Settings
from .database import Registry

def bootstrap(path):
 s=Settings.load(path);s.ca_certificate.parent.mkdir(parents=True,exist_ok=True);s.ca_private_key.parent.mkdir(parents=True,exist_ok=True)
 if s.ca_certificate.exists() or s.ca_private_key.exists():raise SystemExit('CA material exists; refusing overwrite')
 key=rsa.generate_private_key(public_exponent=65537,key_size=3072);now=datetime.now(timezone.utc);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'NLS Router-CA Root')])
 cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now.replace(tzinfo=None)).not_valid_after((now+timedelta(days=3650)).replace(tzinfo=None)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=None,decipher_only=None),critical=True).sign(key,hashes.SHA256())
 s.ca_private_key.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));s.ca_certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM));os.chmod(s.ca_private_key,0o600);os.chmod(s.ca_certificate,0o644)
 token=secrets.token_urlsafe(48);s.token_file.parent.mkdir(parents=True,exist_ok=True);s.token_file.write_text(token+'\n',encoding='ascii');os.chmod(s.token_file,0o600);Registry(s.database_path);print('CA initialized; protect private key and bootstrap token.')
def register(path,router_id,token,public_key_sha256='',ipv6='',mac=''):
 s=Settings.load(path);db=Registry(s.database_path);now=int(time.time())
 with db.connect() as c:c.execute("INSERT INTO routers(router_id,registered,status,expected_public_key_sha256,allowed_ipv6,allowed_mac,enrollment_token_sha256,created_at,updated_at) VALUES(?,1,'ACTIVE',?,?,?,?,?,?) ON CONFLICT(router_id) DO UPDATE SET registered=1,status='ACTIVE',expected_public_key_sha256=excluded.expected_public_key_sha256,allowed_ipv6=excluded.allowed_ipv6,allowed_mac=excluded.allowed_mac,enrollment_token_sha256=excluded.enrollment_token_sha256,updated_at=excluded.updated_at",(router_id,public_key_sha256 or None,ipv6 or None,mac or None,hashlib.sha256(token.encode()).hexdigest(),now,now))
 db.audit('ROUTER_REGISTERED',router_id,'registered by local administrator',now);print('Registered router:',router_id)
def serve(path):
 Settings.load(path);raise SystemExit('TLS listener is not implemented; refusing to start plaintext service')
def main():
 p=argparse.ArgumentParser(prog='nls-router-ca');p.add_argument('--config',default='/etc/nls-nexos-core/router-ca.yaml');sub=p.add_subparsers(dest='cmd',required=True);sub.add_parser('init');sub.add_parser('serve');r=sub.add_parser('register-router');r.add_argument('router_id');r.add_argument('--token',required=True);r.add_argument('--public-key-sha256',default='');r.add_argument('--ipv6',default='');r.add_argument('--mac',default='');a=p.parse_args()
 if a.cmd=='init':bootstrap(a.config)
 elif a.cmd=='serve':serve(a.config)
 else:register(a.config,a.router_id,a.token,a.public_key_sha256,a.ipv6,a.mac)
if __name__=='__main__':main()