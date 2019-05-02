
from cert_utils import *

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)


private_key2 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key2 = private_key2.public_key()

public_key = private_key.public_key()


cert = cert_build_signed(private_key, public_key, "1")
print(cert_validate_signature(cert, public_key2))
