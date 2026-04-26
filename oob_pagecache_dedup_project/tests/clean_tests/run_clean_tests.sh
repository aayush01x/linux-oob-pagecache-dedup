#!/bin/bash
#
# run_clean_tests.sh — (DEPRECATED) Use ../run_all_tests.sh instead.
#
# This script is kept for backwards compatibility.
# It forwards to the central test runner.
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "[!] run_clean_tests.sh is deprecated. Use run_all_tests.sh instead."
echo ""
exec bash "$SCRIPT_DIR/../run_all_tests.sh" "$@"
