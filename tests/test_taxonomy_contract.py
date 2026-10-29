from pathlib import Path

root = Path(__file__).resolve().parents[1]
api = (root / 'backend/app/routers/artifacts.py').read_text()
ui = (root / 'frontend/src/components/forensic/ArtifactCategoryTree.tsx').read_text()
page = (root / 'frontend/src/pages/forensic/ArtifactExplorerPage.tsx').read_text()
assert '"taxonomy": taxonomy' in api
assert '"sub_category": None' in api
assert 'KNOWN_FILE_CATEGORIES' in api
assert 'section.items.map' in ui
assert 'taxonomy={tree.taxonomy}' in page
print('Taxonomy contract static checks passed')
