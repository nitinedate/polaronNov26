# V76 - WhatsApp decryption dependency pin fix

## Problem
Docker builds failed while resolving `wa-crypt-tools>=0.2.0,<0.3.0` because the configured Python package index exposed only `0.0.8` and `0.1.0`.

## Fix
- Pin `whatsapp-chat-exporter[android_backup]==0.13.0`.
- Pin `wa-crypt-tools==0.1.0`.
- Keep Polaron's native WhatsApp CRYPT handling as the primary decryptor.
- Keep `wtsexporter` and `wadecrypt` as controlled examiner-authorized fallbacks.
- Add regression assertions preventing the unavailable `wa-crypt-tools>=0.2.0` range from returning.

## Rationale
The project already uses independently generated wa-crypt-tools 0.1.0 CRYPT12/14/15 regression vectors, and the runtime invokes the packaged `wadecrypt` CLI only when the native decoder cannot complete a supported encrypted backup.

## Build
Rebuild the backend image with no cache after applying this patch so the failed dependency layer is not reused.
