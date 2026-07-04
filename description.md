# Nsec Oracle

Nsec Oracle is a server-side Nostr **signing oracle** for LNbits. It keeps private keys encrypted with the LNbits server secret and lets other installed extensions — and admin-key API clients — sign and encrypt/decrypt through narrowly scoped permissions, without ever exposing the key.

It is for **in-instance** signing, not relay-facing remote signing for external Nostr apps. For external `bunker://` / `nostrconnect://` clients, use the dedicated `nostr_bunker` extension — the two are complementary.

## Features

- Store and label multiple Nostr identities per wallet.
- Sign events with explicit per-key, per-extension, and per-kind permissions.
- Apply positive, paired rate limits with atomic database enforcement.
- Encrypt and decrypt messages with NIP-04 and NIP-44.
- Discover signing requirements declared by other LNbits extensions.
- Review a wallet-scoped signing audit log.
- Export keys using an admin wallet key for backup or migration.

REST operations that sign, encrypt, decrypt, manage permissions, or expose private keys require the wallet admin key. Invoice keys can only retrieve public keys.
