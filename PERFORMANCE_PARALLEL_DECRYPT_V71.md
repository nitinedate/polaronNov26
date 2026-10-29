# V71 - Dependency-aware parallelism, hybrid OCR, progress healing, mobile auto-decrypt

- Default file-level forensic parallelism raised to 10 bounded units (`FORENSIC_MAX_PARALLELISM=10`).
- Independent sidecars share a 10-slot per-job budget and may run from parse/recovery/OCR/media stages when dependencies permit.
- OCR now starts CUDA GLM plus CPU buckets for small PDFs/text documents; CPU-discovered scans remain pending for GPU.
- progressAgent checks every 20 seconds, closes count-complete stages only when no work/I/O remains, and reports active I/O instead of unexplained 99%.
- WhatsApp CRYPT derivation imports an authorized `decryption_keys.txt` key when no registered key exists.
- Decryption writes `DECRYPTING <file>` / `DECRYPTED <file>` logs. Originals are retained. Derived plaintext is registered in case storage and, when the local case export is mounted, saved under `05_Exports/<run>/decrypted/whatsapp/...`.
- Arbitrary ciphertext is not guessed/brute-forced; automatic decryption is limited to supported formats with matching authorized key material.
