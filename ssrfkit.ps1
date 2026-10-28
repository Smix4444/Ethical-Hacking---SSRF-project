# SSRF Lab — launcher for the ssrfkit toolkit (LAB-ONLY).
#
#   ./ssrfkit.ps1            open the interactive menu
#   ./ssrfkit.ps1 audit      run a subcommand directly (recon/weaponize/exploit/
#                            loot/audit/rebind/full/report)
#
# Requires the lab to be running (docker compose up -d --build). Uses -it so the
# interactive menu can read your input. Mounts the toolkit (read-only logic) and
# the reports/ folder; passes any arguments through to ssrfkit.py.
$root = $PSScriptRoot
docker run --rm -it --network ssrf-lab_ssrflab `
  -v "${root}/toolkit:/t" `
  -v "${root}/reports:/out" `
  python:3.12-slim python /t/ssrfkit.py @args
