from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import datetime
from base64 import b64encode, b64decode

class FakePublicKey():
    """
    This is a hack to encapsulate user-defined public key into RSA key object,
    unfortunately the key must be odd.
    """
    def __init__(self, pub_key=None):
        self._key = None
        if pub_key != None:
            self.set_key(pub_key)

    def set_key(self, pub_key):
        self._key = rsa.generate_private_key(
            public_exponent=pub_key,
            key_size=2048,
            backend=default_backend()).public_key()

    def get_key(self):
        return self._key

    def get_key_val(self):
        return self._key.public_numbers().e


def cert_build_signed(ca_priv_key, pub_key_to_store, domain):
    """
    Returns a certificate signed by ca_priv_key, containing pub_key_to_store
    """
    one_day = datetime.timedelta(1, 0, 0)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'samir&ali.io'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pub_key_to_store)
    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName(u'samir&ali.io')]
        ),
        critical=False
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    certificate = builder.sign(
        private_key=ca_priv_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    return certificate


def cert_get_pub_key(cert):
    """
    Returns public_key from x.509 certificate.
    """
    return cert.public_key()


def cert_get_host(cert):
    """
    Returns hostname from certificate.
    """
    return cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def cert_write(path, cert):
    """
    Saves certificate as PEM.
    """
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def cert_load(path):
    """
    Returns certificate from PEM file.
    """
    cert = x509.load_pem_x509_certificate(open(path, 'rb').read(), default_backend())
    return cert

def cert_from_bytes(bytes):
    """
    Returns cert from bytes.
    """
    return x509.load_pem_x509_certificate(bytes, default_backend())

def cert_to_bytes(cert):
    """
    Returns bytes from cert.
    """
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_validate_signature(cert, pub_key):
    """
    Returns True if cert is signed by CA's private key given CA's public_key = pub_key, otherwise,
    it returns False.
    """
    try:
        pub_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(),
                       cert.signature_hash_algorithm)
        return True
    except Exception:
        return False


def private_key_load(path):
    """
    Returns private key from PEM file.
    """
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        return private_key


def private_key_write(path, key):
    """
    Writes private key to a PEM file.
    """
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def public_key_write(path, key):
    """
    Writes public key to a PEM file.
    """
    with open(path, "wb") as f:
        f.write(key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        )


def public_key_load(path):
    """
    Returns public key PEM file.
    """
    return serialization.load_pem_public_key(open(path, 'rb').read(), default_backend())


def public_key_to_bytes(key):
    """
    Returns public key bytes.
    """
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_from_bytes(bytes):
    """
    Returns public key from bytes.
    """
    return serialization.load_pem_public_key(bytes, default_backend())


def public_key_encrypt(msg, key):
    """
    Returns Encrypted message using key.
    """
    ciphertext = key.encrypt(
        msg.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return b64encode(ciphertext)


def private_key_decrypt(ciphertext, key):
    """
    Returns Encrypted message using key.
    """

    ciphertext = b64decode(ciphertext)

    message = (key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))
    return message.decode()


if __name__ == "__main__":
    private_key = rsa.generate_private_key(
        public_exponent=16111995,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()  # Public key to sign the certificate

    key = 50211111111111111111111111  # fake key to store,  for example el gammal key, unfortunately must be odd...
    fake_key = FakePublicKey(key)

    cert = cert_build_signed(private_key, fake_key.get_key(), "ali")
    print(cert_validate_signature(cert, public_key))
    print(cert_get_pub_key(cert).public_numbers().e)  # Check the fake key we attached to the certificate
