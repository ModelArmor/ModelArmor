#!/bin/bash
set -e

echo "[*] Starting Certifier setup..."

#cd /root/certifier-framework-for-confidential-computing
cd
pwd

# Step 1: Setup certifier service


# Step 2: Parse the command passed to the container
case "$1" in
  server)
    echo "[*] Starting as server..."
    shift
    /root/run_server.sh "$@"
    ;;
  client)
    echo "[*] Starting as client..."
    shift
    /root/run_client.sh "$@"
    ;;
  *)
    echo "[!] Invalid argument: '$1'"
    echo "Usage: docker run <image> [server|client] [args]"
    echo "[!] Exiting and removing container..."
    exit 1  # Exits the container immediately
    ;;
esac
