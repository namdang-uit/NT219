import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

COUNTRY = "VN"
ORG = "UIT Crypto Project"
ROOT_COMMON_NAME = "NT219 Local Root CA"
TSP_COMMON_NAME = "Remote Signing Service (TSP)"

ROOT_KEY_PATH = Path("root_ca_key.pem")
ROOT_CERT_PATH = Path("root_ca_cert.pem")
TSP_KEY_PATH = Path("tsp_key.pem")
TSP_CERT_PATH = Path("tsp_cert.pem")

def build_name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

def write_bytes(path: Path, data: bytes) -> None:
    with path.open("wb") as handle:
        handle.write(data)

def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

def serialize_certificate(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(encoding=serialization.Encoding.PEM)

def create_root_ca(now: datetime.datetime) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = build_name(ROOT_COMMON_NAME)

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    return root_key, root_cert

def create_tsp_cert(
    now: datetime.datetime,
    issuer: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    tsp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tsp_subject = build_name(TSP_COMMON_NAME)

    tsp_cert = (
        x509.CertificateBuilder()
        .subject_name(tsp_subject)
        .issuer_name(issuer)
        .public_key(tsp_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(issuer_key, hashes.SHA256())
    )

    return tsp_key, tsp_cert

def main() -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    root_key, root_cert = create_root_ca(now)
    tsp_key, tsp_cert = create_tsp_cert(now, root_cert.subject, root_key)

    write_bytes(ROOT_KEY_PATH, serialize_private_key(root_key))
    write_bytes(ROOT_CERT_PATH, serialize_certificate(root_cert))
    write_bytes(TSP_KEY_PATH, serialize_private_key(tsp_key))
    write_bytes(TSP_CERT_PATH, serialize_certificate(tsp_cert))

    print("Khoi tao Root CA va cap chung thu cho TSP thanh cong!")

if __name__ == "__main__":
    main()