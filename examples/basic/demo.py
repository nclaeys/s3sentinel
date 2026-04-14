"""
s3sentinel basic demo
=====================
Demonstrates the full STS flow:
  1. Fetch an OIDC token from Keycloak for each user.
  2. Exchange it for temporary S3 credentials via the STS endpoint.
  3. Inspect the SessionToken to see the encoded identity claims.
  4. Use those credentials with boto3 — no custom headers needed.

Expected output:
  --- reader session token claims ---
  iss    : s3sentinel-sts
  sub    : reader
  email  : reader@example.com
  groups : ['reader']
  expires: <datetime>
  signature OK: True
  ---
  admin upload: OK
  reader download: quarterly sales data
  reader upload blocked: AccessDenied

Run from the project root after `docker compose -f examples/basic/docker-compose.yml up --build`:
  python3 examples/basic/demo.py
"""

import base64
import datetime
import hashlib
import hmac
import json
import urllib.parse
import urllib.request

import boto3
from botocore.exceptions import ClientError

KEYCLOAK = "http://localhost:8180/realms/s3sentinel/protocol/openid-connect/token"
PROXY = "http://localhost:8080"
STS = "http://localhost:8090"
BUCKET = "example-bucket"

# Must match STS_TOKEN_SECRET in docker-compose.yml.
STS_SECRET = b"dev-only-change-this-secret-in-production"


def get_jwt_token(username: str, password: str) -> str:
    data = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "s3sentinel",
            "username": username,
            "password": password,
        }
    ).encode()
    with urllib.request.urlopen(KEYCLOAK, data) as r:
        return json.load(r)["access_token"]


def assume_role(token: str) -> dict:
    """Exchange an OIDC token for temporary S3 credentials via the STS endpoint."""
    sts = boto3.client(
        "sts",
        endpoint_url=STS,
        aws_access_key_id="placeholder",
        aws_secret_access_key="placeholder",
        region_name="us-east-1",
    )
    resp = sts.assume_role_with_web_identity(
        RoleArn="arn:aws:iam::000000000000:role/s3sentinel",
        RoleSessionName="demo",
        WebIdentityToken=token,
    )
    return resp["Credentials"]


def decode_session_token(token: str) -> dict:
    """Decode the JWT payload without verifying the signature.

    The payload is the middle segment of the dot-separated JWT string.
    It is base64url-encoded JSON — no secret is needed to read it.
    Anyone who holds the token can see these claims; the HMAC signature
    on the third segment is what prevents them from being altered.
    """
    payload_b64 = token.split(".")[1]
    padding = 4 - len(payload_b64) % 4
    return json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * padding))


def verify_session_token(token: str, secret: bytes) -> bool:
    """Verify the HMAC-SHA256 signature on a SessionToken JWT.

    Returns True if the signature is valid, False if the token has been
    tampered with. This is the same check the proxy performs on every request.
    """
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=")
    return hmac.compare_digest(expected_b64, sig_b64.encode())


def print_session_token(label: str, token: str, secret: bytes) -> None:
    claims = decode_session_token(token)
    expiry = datetime.datetime.fromtimestamp(claims["exp"], tz=datetime.timezone.utc)
    sig_ok = verify_session_token(token, secret)
    print(f"--- {label} session token claims ---")
    print(f"  iss    : {claims.get('iss')}")
    print(f"  sub    : {claims.get('sub')}")
    print(f"  email  : {claims.get('email')}")
    print(f"  groups : {claims.get('groups')}")
    print(f"  expires: {expiry}")
    print(f"  signature OK: {sig_ok}")
    print("---")


def s3_client(creds: dict):
    return boto3.client(
        "s3",
        endpoint_url=PROXY,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name="us-east-1",
    )


def main() -> None:
    reader_token = get_jwt_token("reader", "reader123")
    reader_creds = assume_role(reader_token)
    print_session_token("reader", reader_creds["SessionToken"], STS_SECRET)

    admin_creds = assume_role(get_jwt_token("admin", "admin123"))
    print_session_token("admin", admin_creds["SessionToken"], STS_SECRET)
    admin_s3 = s3_client(admin_creds)
    admin_s3.put_object(
        Bucket=BUCKET,
        Key="reports/report.csv",
        Body=b"quarterly sales data",
    )
    print("admin upload: OK")

    reader_s3 = s3_client(reader_creds)
    obj = reader_s3.get_object(Bucket=BUCKET, Key="reports/report.csv")
    print("reader download:", obj["Body"].read().decode())

    try:
        reader_s3.put_object(
            Bucket=BUCKET,
            Key="reports/malicious.csv",
            Body=b"this should not be allowed",
        )
        print("reader upload: ERROR — should have been denied")
    except ClientError as e:
        print("reader upload blocked:", e.response["Error"]["Code"])  # AccessDenied


if __name__ == "__main__":
    main()
