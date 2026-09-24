#!/usr/bin/env bash
# Variables from the job are exported before this script runs (e.g. $ntp_server).
set -euo pipefail
systemctl restart chrony
systemctl is-active --quiet chrony
echo "chrony restarted, upstream ${ntp_server}"
