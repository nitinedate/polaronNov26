from pathlib import Path
s = Path('backend/app/services/artifact_preview.py').read_text()
assert 'if content_type == "application/pdf":' in s
assert s.index('if content_type == "application/pdf":') < s.index('data = resolve_artifact_bytes(')
a = Path('frontend/src/components/forensic/ArtifactPreviewPanel.tsx').read_text()
assert 'controller.abort(), 20_000' in a
assert 'setContentError(' in a
assert 'URL.revokeObjectURL(objectUrl)' in a
f = Path('frontend/src/lib/forensicApi.ts').read_text()
assert 'signal?: AbortSignal' in f
assert 'signal: opts?.signal' in f
print('Patch contract checks passed')
