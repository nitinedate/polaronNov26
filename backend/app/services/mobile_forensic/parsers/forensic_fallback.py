"""Conservative source-level classification of otherwise unhandled acquired files.

Never claims to decode an unknown or encrypted payload. Keeps a source-linked
inventory record visible to examiners for every unsupported file.
"""
from __future__ import annotations
import json
from email import policy
from email.parser import BytesParser
from pathlib import PurePosixPath
from app.services.mobile_forensic.models import NormalizedArtifact
from app.services.mobile_forensic.plugins import ArtifactParser

_EMAIL = {'.eml', '.emlx', '.mbox'}
_SIGNATURES = ((b'SQLite format 3\x00', 'sqlite'), (b'%PDF-', 'pdf'),
               (b'PK\x03\x04', 'zip_container'), (b'\x89PNG\r\n\x1a\n', 'png'),
               (b'\xff\xd8\xff', 'jpeg'), (b'GIF8', 'gif'),
               (b'\x7fELF', 'elf_binary'), (b'MZ', 'portable_executable'),
               (b'\x1f\x8b', 'gzip'), (b'RIFF', 'riff_container'))


def classify_header(data: bytes) -> str:
    for signature, kind in _SIGNATURES:
        if data.startswith(signature):
            return kind
    if len(data) >= 12 and data[4:8] == b'ftyp':
        return 'iso_media'
    if data and b'\x00' not in data[:512]:
        try:
            data[:2048].decode('utf-8')
            return 'text_candidate'
        except UnicodeDecodeError:
            pass
    return 'unidentified_binary' if data else 'empty'


def _artifact(item, context, kind, data, state='allocated', row_id=None):
    return NormalizedArtifact.create(
        artifact_type=kind, source_domain='email' if kind == 'email_message' else 'files',
        data=data, state=state, source_path=item.path, source_sha256=item.sha256,
        source_row_id=row_id, parser='forensic_fallback', parser_version='1.0.0',
        job_id=context.job_id, source_id=context.source_id,
        recovery_source='acquired_file')


def parse_email_bytes(raw: bytes, extension: str):
    """Return a bounded message summary; do not silently discard attachments."""
    if extension == '.emlx':
        head, sep, rest = raw.partition(b'\n')
        if sep and head.strip().isdigit():
            raw = rest[:int(head.strip())]
    message = BytesParser(policy=policy.default).parsebytes(raw)
    headers = {name: str(message.get(name, ''))[:4096]
               for name in ('From', 'To', 'Cc', 'Bcc', 'Date', 'Subject', 'Message-ID')}
    bodies = []
    attachments = []
    parts = list(message.walk()) if message.is_multipart() else [message]
    for part in parts[:2000]:
        if part.is_multipart():
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b''
        if filename or part.get_content_disposition() == 'attachment':
            attachments.append({'name': str(filename or 'unnamed')[:512],
                                'mime': part.get_content_type(), 'size': len(payload)})
        elif part.get_content_type() in ('text/plain', 'text/html'):
            charset = part.get_content_charset() or 'utf-8'
            try:
                body = payload[:65536].decode(charset, errors='replace')
            except LookupError:
                body = payload[:65536].decode('utf-8', errors='replace')
            bodies.append({'mime': part.get_content_type(), 'text': body,
                           'truncated': len(payload) > 65536})
    return {'headers': headers, 'bodies': bodies[:8], 'attachments': attachments[:500],
            'attachment_count': len(attachments), 'body_parts_count': len(bodies),
            'content_truncated': len(parts) > 2000 or len(attachments) > 500 or len(bodies) > 8}


class ForensicFallbackParser(ArtifactParser):
    name = 'forensic_fallback'
    domains = ('files', 'email')

    def supports(self, item, context):
        return True

    def parse(self, item, context):
        ext = (item.extension or PurePosixPath(item.path).suffix or '').lower()
        meta = item.meta if isinstance(item.meta, dict) else {}
        base = {'path': item.path, 'name': PurePosixPath(item.path).name,
                'size': item.size, 'sha256': item.sha256, 'extension': ext,
                'mime_hint': item.mime_hint, 'source_metadata': {
                    k: v for k, v in meta.items() if k in ('detected_mime', 'is_deleted', 'inode', 'file_offset')
                }}
        max_read = 16 * 1024 * 1024 if ext in _EMAIL else 4096
        raw = context.read_artifact_bytes(item.path, max_bytes=max_read)
        if raw is None:
            base.update(recognition='unreadable', examination_status='source_unavailable')
            yield _artifact(item, context, 'unclassified_file', base, 'unsupported')
            return
        header = raw[:4096]
        recognized = classify_header(header)
        base.update(recognition=recognized, header_hex=header[:32].hex(),
                    examination_status='metadata_only', source_read_bytes=len(raw))
        if ext in _EMAIL:
            if item.size and item.size > max_read:
                base['examination_status'] = 'email_too_large_for_bounded_parser'
            else:
                try:
                    if ext == '.mbox':
                        # Mbox envelope separators start at the beginning of a line.
                        # Each message is a separate, source-linked artifact.
                        chunks = []
                        current = []
                        for line in raw.splitlines(keepends=True):
                            if line.startswith(b'From ') and current:
                                chunks.append(b''.join(current))
                                current = []
                            elif line.startswith(b'From ') and not current:
                                continue
                            current.append(line)
                        if current:
                            chunks.append(b''.join(current))
                        for index, message_bytes in enumerate(chunks[:10000]):
                            info = parse_email_bytes(message_bytes, '.eml')
                            yield _artifact(item, context, 'email_message',
                                            {**base, **info, 'examination_status': 'mbox_message_decoded',
                                             'message_index': index,
                                             'mailbox_truncated': len(chunks) > 10000},
                                            row_id=str(index))
                        if chunks:
                            return
                        base['examination_status'] = 'mbox_no_messages_detected'
                    else:
                        info = parse_email_bytes(raw, ext)
                        base.update(info, examination_status='email_decoded')
                        yield _artifact(item, context, 'email_message', base)
                        return
                except Exception as exc:
                    base['examination_status'] = 'email_parse_error'
                    base['parse_error'] = str(exc)[:300]
        elif recognized == 'text_candidate' and item.size <= max_read:
            base['text_preview'] = raw[:2048].decode('utf-8', errors='replace')
            base['examination_status'] = 'text_preview_only'
        yield _artifact(item, context, 'unclassified_file', base, 'unsupported')
