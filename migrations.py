from lnbits.db import Connection


async def m001_initial(db: Connection):
    """
    Create the Nsec Oracle schema, or adopt an existing ``nsecbunker`` install.

    Nsec Oracle was previously published as the ``nsecbunker`` extension. When
    upgrading from it on PostgreSQL/CockroachDB, move the existing keys,
    permissions and signing-log tables into this extension's schema so stored
    keys and grants carry over untouched. A fresh install simply creates the
    tables at their final shape. (On SQLite the legacy tables are not adopted;
    export and re-import keys instead.)
    """
    if db.type in {"POSTGRES", "COCKROACH"} and await _legacy_nsecbunker_present(db):
        await _adopt_legacy_nsecbunker(db)
        return

    await db.execute(
        """
        CREATE TABLE nsec_oracle.keys (
            id TEXT PRIMARY KEY,
            wallet TEXT NOT NULL,
            pubkey_hex TEXT NOT NULL,
            encrypted_nsec TEXT NOT NULL,
            label TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    await db.execute(
        """
        CREATE TABLE nsec_oracle.permissions (
            id TEXT PRIMARY KEY,
            wallet TEXT NOT NULL,
            extension_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            kind INTEGER NOT NULL,
            rate_limit_count INTEGER,
            rate_limit_seconds INTEGER,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    await db.execute(
        "CREATE INDEX idx_permissions_wallet_ext "
        "ON nsec_oracle.permissions (wallet, extension_id, kind)"
    )
    await db.execute(
        """
        CREATE TABLE nsec_oracle.signing_log (
            id TEXT PRIMARY KEY,
            key_id TEXT NOT NULL,
            extension_id TEXT NOT NULL,
            kind INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )


async def _legacy_nsecbunker_present(db: Connection) -> bool:
    row = await db.fetchone(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = 'nsecbunker' AND table_name = 'keys'"
    )
    return row is not None


async def _adopt_legacy_nsecbunker(db: Connection):
    # Move the data-bearing tables (with their indexes/constraints) into this
    # extension's schema, discard the removed NIP-46 connections table, then drop
    # the now-empty legacy schema.
    for table in ("keys", "permissions", "signing_log"):
        await db.execute(
            f"ALTER TABLE IF EXISTS nsecbunker.{table} SET SCHEMA nsec_oracle"
        )
    await db.execute("DROP TABLE IF EXISTS nsecbunker.connections")
    await db.execute("DROP SCHEMA IF EXISTS nsecbunker CASCADE")
