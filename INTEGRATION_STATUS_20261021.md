# Complete merged Polaron source - 2026-10-21

Base: polaron(20261020-153028).zip.

Integrated the previous targeted patches in this sequence:
1. Stage/parse restart mitigation
2. Standard/Deep processing mode
3. Mobile Android TS2367 fix
4. Validation get_settings import fix
5. Artifact blank-page guards
6. Artifact category and indexing changes
7. Taxonomy tree integration
8. Preview repair
9. processing_profile TS2353 correction
10. Deleted-evidence timeout mitigation
11. Typed getArtifactTaxonomy API insertion (TS2339/TS7006)

Verification: backend Python compileall passed; API helper includes both processing_profile and getArtifactTaxonomy. Full frontend build NOT verified: offline npm install failed because yallist-3.1.1 was unavailable in npm cache. Live PostgreSQL, MinIO, Neo4j, forensic recovery tests NOT run. Any pending migration must be applied separately to each appropriate DB/schema after reviewing the migration.

This is a merged source snapshot, NOT a production certification. Keep original DB and MinIO volumes. Run npm ci and npm run build:mobile-android in a normal network-enabled dev environment; also build other frontend modes and run test suites before deployment.
