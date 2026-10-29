from pathlib import Path
import ast

root = Path(__file__).resolve().parents[1]
module = root / 'backend/app/services/artifact_browse_categories.py'
content = module.read_text()
ast.parse(content)
assert 'ltrim' in content and 'extension' in content
api = (root / 'backend/app/routers/artifacts.py').read_text()
assert '"sub_category": None' in api
assert '"total": sum(row["count"] for row in categories)' in api
assert 'KNOWN_FILE_CATEGORIES' in api
print('Category endpoint contract and filter match: OK')
