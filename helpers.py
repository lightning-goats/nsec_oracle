from pynostr.key import PrivateKey


def parse_nostr_private_key(key: str) -> PrivateKey:
    """Parse a Nostr private key from an ``nsec`` (bech32) or 64-char hex string.

    Raises ``ValueError`` on anything that is not a well-formed key. This is
    deliberately strict: ``pynostr`` will happily accept a wrong-length byte
    string (e.g. a truncated 31-byte hex paste) as a "valid" private key, which
    would then be stored as a valid-but-wrong key. Rejecting malformed input up
    front prevents that silent corruption.
    """
    key = key.strip()
    if not key:
        raise ValueError("Empty Nostr private key")

    if key.startswith("nsec"):
        try:
            return PrivateKey.from_nsec(key)
        except Exception as exc:
            raise ValueError("Invalid nsec (bech32) private key") from exc

    if len(key) != 64:
        raise ValueError("Hex private key must be exactly 64 characters")
    try:
        raw = bytes.fromhex(key)
    except ValueError as exc:
        raise ValueError("Private key is not valid hex") from exc
    return PrivateKey(raw)
