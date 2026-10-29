# Polaron V1.17.3: start_docker no longer hangs after restarting the phone helper

`script_docker\start_docker_*.cmd` stopped after "Host drive helper is online" and never printed READY.
Everything had already started; the launcher was waiting on output that never ends: it piped the helper setup's
output, and the helper that setup starts keeps running in the background holding that output open.

The launcher now waits for the setup script to exit (up to 15 minutes, for a first-time examiner-kit download),
shows its log line by line as before, then checks the helper and prints READY.

If a launch is waiting at that line now, press Ctrl+C: all stacks and the helper are already running.
