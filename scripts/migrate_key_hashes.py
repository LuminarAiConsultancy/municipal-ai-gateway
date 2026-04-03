#!/usr/bin/env python3
"""One-time migration: hash existing plaintext API keys.

Run AFTER applying Alembic migration 002_hash_api_keys:

    cd gateway
    alembic upgrade head
    python ../scripts/migrate_key_hashes.py

This script:
  1. Reads all api_keys rows that still have a plaintext `key` column.
  2. Computes SHA-256 hash and stores it in `key_hash`.
  3. Stores the first 8 chars as `key_prefix` for display.
  4. Nulls out the plaintext `key` column.

IMPORTANT: After running, plaintext keys are gone. Staff who lose their key
must have a new one generated.
"""

import os
import sys
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://gateway:changeme@db:5432/ai_gateway",
)
SYNC_URL = DATABASE_URL.replace("+asyncpg", "")

engine = create_engine(SYNC_URL)


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def main():
    with Session(engine) as session:
        rows = session.execute(
            text("SELECT id, key FROM api_keys WHERE key IS NOT NULL AND key_hash IS NULL")
        ).fetchall()

        if not rows:
            print("No un-migrated keys found. Nothing to do.")
            return

        print(f"Migrating {len(rows)} key(s)...")
        for row in rows:
            key_id, plaintext = row
            hashed = hash_key(plaintext)
            prefix = plaintext[:8]
            session.execute(
                text(
                    "UPDATE api_keys SET key_hash = :hash, key_prefix = :prefix, key = NULL "
                    "WHERE id = :id"
                ),
                {"hash": hashed, "prefix": prefix, "id": key_id},
            )
            print(f"  Key {key_id} ({prefix}...): hashed")

        session.commit()
        print("Done. Plaintext keys have been removed.")


if __name__ == "__main__":
    main()
