"""
s3sentinel parquet demo
=======================
Demonstrates writing a large Parquet file to MinIO through the s3sentinel proxy
and querying it in-place with DuckDB — no local copy needed.

Flow:
  1. Admin authenticates via Keycloak OIDC → STS → temporary S3 credentials.
  2. Generate ~50 MB of synthetic transaction data with PyArrow and upload as
     Parquet to example-bucket/data/transactions.parquet via the proxy.
  3. Reader authenticates the same way (read-only credentials).
  4. DuckDB reads the Parquet file directly from the proxy with httpfs and runs
     two analytical queries — no local download required.

Run after `docker compose -f examples/basic/docker-compose.yml up --build`:
  pip install boto3 pyarrow duckdb
  python3 examples/basic/parquet_demo.py
"""

import io
import json
import urllib.parse
import urllib.request
import time

import boto3
import duckdb
import pyarrow as pa
import pyarrow.parquet as pq
import numpy as np

KEYCLOAK = "http://localhost:8180/realms/s3sentinel/protocol/openid-connect/token"
STS = "http://localhost:8090"
PROXY = "http://localhost:8080"
BUCKET = "example-bucket"
PARQUET_KEY = "data/transactions.parquet"

NUM_ROWS = 1_000_000  # ~50 MB on disk as Parquet


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
    sts = boto3.client(
        "sts",
        endpoint_url=STS,
        aws_access_key_id="placeholder",
        aws_secret_access_key="placeholder",
        region_name="us-east-1",
    )
    resp = sts.assume_role_with_web_identity(
        RoleArn="arn:aws:iam::000000000000:role/s3sentinel",
        RoleSessionName="parquet-demo",
        WebIdentityToken=token,
    )
    return resp["Credentials"]


def s3_client(creds: dict):
    return boto3.client(
        "s3",
        endpoint_url=PROXY,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name="us-east-1",
    )


def generate_transactions(n: int) -> pa.Table:
    """Return a PyArrow Table with synthetic transaction data."""
    rng = np.random.default_rng(42)

    categories = ["electronics", "clothing", "groceries", "travel", "dining"]
    regions = ["eu-west", "eu-central", "us-east", "us-west", "ap-southeast"]
    status_vals = ["completed", "pending", "refunded"]

    return pa.table(
        {
            "transaction_id": pa.array(np.arange(n, dtype=np.int64)),
            "user_id": pa.array(rng.integers(1, 50_000, size=n, dtype=np.int32)),
            "amount_eur": pa.array(
                np.round(rng.exponential(scale=80.0, size=n), 2).astype(np.float64)
            ),
            "category": pa.array(
                [categories[i] for i in rng.integers(0, len(categories), size=n)]
            ),
            "region": pa.array(
                [regions[i] for i in rng.integers(0, len(regions), size=n)]
            ),
            "status": pa.array(
                [status_vals[i] for i in rng.integers(0, len(status_vals), size=n)]
            ),
            # Timestamps spread over 2 years (seconds since epoch).
            "ts": pa.array(
                (1_640_000_000 + rng.integers(0, 2 * 365 * 86_400, size=n)).astype(
                    np.int64
                ),
                type=pa.timestamp("s"),
            ),
            # 32-char hex description string to bulk up file size.
            "description": pa.array(
                [
                    "".join(
                        rng.choice(list("0123456789abcdef"), 32).tolist()
                    )
                    for _ in range(n)
                ]
            ),
        }
    )


def upload_parquet(table: pa.Table, creds: dict) -> int:
    """Serialise table to Parquet in memory and upload via the proxy."""
    buf = io.BytesIO()
    pq.write_table(
        table,
        buf,
        compression="snappy",
        row_group_size=200_000,
    )
    size = buf.tell()
    buf.seek(0)

    s3 = s3_client(creds)
    s3.upload_fileobj(buf, BUCKET, PARQUET_KEY)
    return size


def run_duckdb_queries(creds: dict) -> None:
    con = duckdb.connect()
    con.execute("INSTALL httpfs; LOAD httpfs;")
    con.execute(f"""
        SET s3_endpoint='localhost:8080';
        SET s3_access_key_id='{creds["AccessKeyId"]}';
        SET s3_secret_access_key='{creds["SecretAccessKey"]}';
        SET s3_session_token='{creds["SessionToken"]}';
        SET s3_use_ssl=false;
        SET s3_url_style='path';
    """)

    parquet_url = f"s3://{BUCKET}/{PARQUET_KEY}"

    print("\n── query 1: revenue by category (completed only) ─────────────────")
    rows = con.execute(f"""
        SELECT
            category,
            COUNT(*)          AS tx_count,
            ROUND(SUM(amount_eur), 2) AS total_eur,
            ROUND(AVG(amount_eur), 2) AS avg_eur
        FROM read_parquet('{parquet_url}')
        WHERE status = 'completed'
        GROUP BY category
        ORDER BY total_eur DESC
    """).fetchall()
    print(f"  {'category':<14} {'tx_count':>10} {'total_eur':>14} {'avg_eur':>10}")
    print(f"  {'-'*14} {'-'*10} {'-'*14} {'-'*10}")
    for row in rows:
        print(f"  {row[0]:<14} {row[1]:>10,} {row[2]:>14,.2f} {row[3]:>10.2f}")

    print("\n── query 2: monthly revenue (all regions, completed) ─────────────")
    rows = con.execute(f"""
        SELECT
            strftime(ts, '%Y-%m')        AS month,
            COUNT(*)                      AS tx_count,
            ROUND(SUM(amount_eur), 2)     AS total_eur
        FROM read_parquet('{parquet_url}')
        WHERE status = 'completed'
        GROUP BY month
        ORDER BY month
        LIMIT 12
    """).fetchall()
    print(f"  {'month':<10} {'tx_count':>10} {'total_eur':>14}")
    print(f"  {'-'*10} {'-'*10} {'-'*14}")
    for row in rows:
        print(f"  {row[0]:<10} {row[1]:>10,} {row[2]:>14,.2f}")

    con.close()


def main() -> None:
    print(f"generating {NUM_ROWS:,} rows of transaction data …")
    table = generate_transactions(NUM_ROWS)
    print(f"  PyArrow table: {table.num_rows:,} rows × {table.num_columns} columns")

    print("\nauthenticating admin …")
    admin_creds = assume_role(get_jwt_token("admin", "admin123"))
    print("  STS credentials issued")

    print(f"\nuploading Parquet to s3://{BUCKET}/{PARQUET_KEY} …")
    start_time = time.time()
    size_bytes = upload_parquet(table, admin_creds)
    end_time = time.time()
    print(f"  uploaded {size_bytes / 1_048_576:.1f} MB in {end_time - start_time:.2f} seconds")

    print("\nauthenticating reader …")
    reader_creds = assume_role(get_jwt_token("reader", "reader123"))
    print("  STS credentials issued (read-only)")

    print("\nquerying Parquet via DuckDB + httpfs …")
    run_duckdb_queries(reader_creds)


if __name__ == "__main__":
    main()
