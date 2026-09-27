#!/usr/bin/env bash
# Variables from the job are exported before this script runs (e.g. $ntp_server).
set -euo pipefail
systemctl restart chrony
systemctl is-active --quiet chrony
# shellcheck disable=SC2154 # exported by RCO, see above
echo "chrony restarted, upstream ${ntp_server}"
