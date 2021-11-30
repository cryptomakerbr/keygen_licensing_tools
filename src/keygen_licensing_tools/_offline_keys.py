"""
See also
https://github.com/keygen-sh/example-python-cryptographic-verification
"""
import base64
import json

import ed25519
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from ._exceptions import ValidationError
from ._helpers import to_datetime


def validate_offline_key(
    license_scheme: str, license_key: str, keygen_verify_key: str
) -> dict:
    signing_data, enc_sig = license_key.split(".")
    prefix, enc_key = signing_data.split("/")
    assert prefix == "key", f"license key prefix {prefix} is invalid"

    sig = base64.urlsafe_b64decode(enc_sig)
    key = base64.urlsafe_b64decode(enc_key)

    msg = f"key/{enc_key}".encode()

    if license_scheme == "ED25519_SIGN":
        _verify_ed25519(keygen_verify_key, sig, msg)
    else:
        _verify_rsa(license_scheme, keygen_verify_key, sig, msg)

    data = json.loads(key)

    # convert some strings to datetime objects
    if "license" in data:
        lic = data["license"]
        for key in ["created", "expiry"]:
            if key in lic:
                lic[key] = to_datetime(lic[key])

    return data


def _verify_ed25519(keygen_verify_key, sig, msg):
    verify_key = ed25519.VerifyingKey(keygen_verify_key.encode(), encoding="hex")
    try:
        verify_key.verify(sig, msg)
    except ed25519.BadSignatureError:
        raise ValidationError("Key validation failed", "ERR")


def _verify_rsa(license_scheme, keygen_verify_key, sig, msg):
    assert license_scheme in ["RSA_2048_PKCS1_SIGN_V2", "RSA_2048_PKCS1_PSS_SIGN_V2"]

    # Load the PEM formatted public key from the env
    pub_key = serialization.load_pem_public_key(
        keygen_verify_key.encode(), backend=default_backend()
    )

    # Choose the correct padding based on the chosen scheme
    if license_scheme == "RSA_2048_PKCS1_PSS_SIGN_V2":
        pad = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        )
    else:
        pad = padding.PKCS1v15()

    # Verify the license
    try:
        pub_key.verify(sig, msg, pad, hashes.SHA256())
    except (InvalidSignature, TypeError):
        raise ValidationError("Key validation failed", "ERR")
