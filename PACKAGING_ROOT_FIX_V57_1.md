# Polaron V57.1 Packaging Root Fix

The previous V57 complete ZIP contained the project under a top-level `polaron_v56_whatsapp_gate` directory. If its contents were not copied one level up, startup from `F:\polaron-forensic` could not find `tools\host-python-requirements.txt` and other required root-relative deployment files.

This V57.1 package is flattened: `.env.example`, `docker-compose.yml`, `tools`, `script_docker`, `backend`, `frontend`, `services`, and the rest of the project are at the ZIP root.

For a patch-only repair, copy `tools\host-python-requirements.txt` into the existing project root so the final path is:

`F:\polaron-forensic\tools\host-python-requirements.txt`

Do not place it under `script_docker\tools` or another nested project directory.
