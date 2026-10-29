# V69 — Parser coverage + decryption key sidecar

## Parser audit
The project already had native/specialized parsers for Windows Registry hives, EVTX, MFT metadata, Prefetch, LNK, Jump Lists, Recycle Bin, SetupAPI, SQLite/browser/WhatsApp databases, EML/EMLX/MBOX/MSG, structured JSON/XML/CSV/plist/protobuf and mobile application artifacts. It also had signature/type resolution and deleted SQLite/WAL/journal recovery.

V69 closes two important coverage gaps:

1. Common document extensions (PDF, Word, Excel, PowerPoint, RTF and OpenDocument) are routed through a document-text parser during native parsing. Existing preview/OCR extraction code is reused; if native text cannot be extracted, the evidence falls through to the binary parser rather than becoming an empty/no-parser record.
2. Every unknown/extensionless/proprietary binary now receives a bounded universal binary parse containing SHA-256, magic/type hint, entropy and offset-labelled ASCII/UTF-8/UTF-16 readable strings. It deliberately does not invent application/message semantics.

No finite parser set can decode every proprietary binary format. V69 therefore provides specialized parsing where the format is understood and a deterministic binary fallback everywhere else.

## 05_Exports key sidecar
After a live mobile acquisition creates the portable package set, V69 writes:

`05_Exports/<run>/decryption_keys.txt`

It is a key=value file containing only already acquired or examiner-authorized decryption material. WhatsApp key files are preserved as base64 plus SHA-256 and, when recognized, the usable 32-byte key hex is also emitted. iOS backup passwords supplied for the acquisition are included. Keybag/escrow material is preserved as base64 with source path and hash. Secret values are never written to application logs.

The writer attempts mode 0600. On Windows, filesystem ACLs remain authoritative; the containing case/export directory should therefore remain examiner-restricted.

The portable evidence packages remain the same four package formats; `decryption_keys.txt` is an intentional private sidecar and is not automatically embedded into those packages.
