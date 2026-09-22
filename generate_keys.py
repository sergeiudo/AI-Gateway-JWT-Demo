import json
import uuid
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    return base64.urlsafe_b64encode(bytes.fromhex(value_hex)).rstrip(b'=').decode('utf-8')

# 1. Generate RSA 2048-bit Key Pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
numbers = private_key.public_key().public_numbers()
kid = str(uuid.uuid4())

# 2. Build JWKS JSON (Public Key only)
jwks = {
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": int_to_base64(numbers.n),
        "e": int_to_base64(numbers.e)
    }]
}

# Save files
with open("jwks.json", "w") as f:
    json.dump(jwks, f, indent=2)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open("private_key.pem", "wb") as f:
    f.write(pem)

print("--- KEY GENERATION SUCCESSFUL ---")
print(f"Key ID (kid): {kid}")
print("Saved: 'private_key.pem' and 'jwks.json'")