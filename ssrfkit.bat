@echo off
REM SSRF Lab — launcher for the ssrfkit toolkit (LAB-ONLY).
REM   ssrfkit.bat          open the interactive menu
REM   ssrfkit.bat audit    run a subcommand directly
REM Requires the lab running (docker compose up -d --build). -it = interactive.
docker run --rm -it --network ssrf-lab_ssrflab -v "%~dp0toolkit:/t" -v "%~dp0reports:/out" python:3.12-slim python /t/ssrfkit.py %*
