#!/usr/bin/env bash
set -euo pipefail
[ -n "$BASH_VERSION" ]
# shellcheck disable=SC2154 # job variables are exported by RCO
echo "bash says $greeting"
