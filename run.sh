#!/bin/bash
# Run the Xray Connection Manager GUI
cd "$(dirname "$0")"
exec python3 -m xray_manager "$@"
