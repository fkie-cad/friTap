# GDB TLS Key Extraction (Planned)

TLS key extraction via GDB is planned for the future.

## Approach
- Hook HKDF-Expand-Label (TLS 1.3) and PRF (TLS 1.2) functions
- Use byte patterns from TLSKeyHunter research
- Extract key material at function return

## References
- https://github.com/monkeywave/TLSKeyHunter
