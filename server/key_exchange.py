from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# Generate parameters ONCE
parameters = dh.generate_parameters(generator=2, key_size=2048)

def get_parameters_bytes():
    return parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )

def load_parameters(parameter_bytes):
    return serialization.load_pem_parameters(parameter_bytes)

def generate_dh_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_bytes

def load_peer_public_key(peer_public_bytes):
    return serialization.load_pem_public_key(peer_public_bytes)

def generate_shared_secret(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)