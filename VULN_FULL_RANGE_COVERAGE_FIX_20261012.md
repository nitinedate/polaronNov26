# Vulnerability scan coverage correction (2026-10-12)

This project is the **central Polaron server**. The companion laptop/edge agent must be deployed separately to change its actual probe scope.

## Updated central behavior
- The central scan-details assessment distinguishes engine completion from verified service-family coverage.
- Clean eligible is denied unless every intended target has explicitly completed service coverage with no not-tested or unsupported families.
- Missing service coverage fails closed rather than showing a clean assessment.
- UI displays Service coverage verified alongside engine assessment.
- Existing GVM_PORT_PROFILE=full (all TCP ports, 1-65535) remains the central default; actual checks depend on the client agent and Greenbone feeds.

## Deployment
Use your existing production startup procedure after backing up the current installation and environment. No DB migration, evidence deletion, or Docker volume destruction is required by this patch. Existing historical scan reports remain incomplete and must be rerun for new coverage data.

## Limitations
This update does not add new Greenbone NVT signatures or guarantee that every service family can be authenticated or assessed. Verify Greenbone feed readiness and deploy the corresponding full-range laptop scanner on the remote scanning host.
