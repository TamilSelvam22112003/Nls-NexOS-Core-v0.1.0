from nls_nexos_core.config import Settings

def test_load_config(tmp_path):
    p=tmp_path/'ca.yaml'; p.write_text('server:\n  host: 127.0.0.1\n  port: 8443\ndatabase:\n  path: /tmp/test.db\npki:\n  ca_certificate: /tmp/ca.crt\n  ca_private_key: /tmp/ca.key\n  issued_cert_dir: /tmp/issued\nenrollment:\n  token_file: /tmp/token\n  certificate_days: 30\n')
    s=Settings.load(p); assert s.port==8443; assert s.certificate_days==30
