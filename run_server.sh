#!/bin/bash

set -e

export CERTIFIER_PROTOTYPE=/root/certifier-framework-for-confidential-computing
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app

cd $EXAMPLE_DIR

# Extract --host argument (default to 127.0.0.1 if not passed)
HOST_ARG="--host=127.0.0.1"
REMAINING_ARGS=()

for arg in "$@"; do
  if [[ "$arg" == --host=* ]]; then
    HOST_ARG="$arg"
  else
    REMAINING_ARGS+=("$arg")
  fi
done

echo "[*] Starting Certifier Service with $HOST_ARG ..."
cd service
$CERTIFIER_PROTOTYPE/certifier_service/simpleserver --policyFile=policy.bin --readPolicy=true "$HOST_ARG" &

# Save the PID to kill later if needed
SERVICE_PID=$!

# Give it a moment to start up
sleep 10

# Cold init
echo "[*] Running cold init"
cd $EXAMPLE_DIR
$EXAMPLE_DIR/example_app.exe \
  --data_dir=./app2_data/ \
  --operation=cold-init \
  --measurement_file="example_app.measurement" \
  --policy_store_file=policy_store \
  --print_all=true \
  "${REMAINING_ARGS[@]}"

# Get certified
echo "[*] Running get certified"
$EXAMPLE_DIR/example_app.exe \
  --data_dir=./app2_data/ \
  --operation=get-certified \
  --measurement_file="example_app.measurement" \
  --policy_store_file=policy_store \
  --print_all=true \
  "${REMAINING_ARGS[@]}"

# Run as server with remaining args
echo "[*] Running app as server"
$EXAMPLE_DIR/example_app.exe \
  --data_dir=./app2_data/ \
  --operation=run-app-as-server \
  --policy_store_file=policy_store \
  --print_all=true \
  "${REMAINING_ARGS[@]}"


# docker run --name ccfl-server --network ccfl-net \
#   -p 8123:8123 -p 8124:8124 \
#   ccfl:latest server  --host=127.0.0.1 \
#   --venv_activate=/root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/venv/bin/activate 
#   --policy_host=127.0.0.1 --server_app_host=127.0.0.1


# docker run --name ccfl-client --network ccfl-net \
#   ccfl:latest client \
#   --client_script=client.py \
#   --venv_activate=/root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/venv/bin/activate \
#   --client_id=1
#   --policy_host=127.0.0.1 --server_app_host=127.0.0.1

#   docker run --name ccfl-client --network ccfl-net bwbgv/ccfl client --server_app_host=172.31.20.110 --policy_host=172.31.20.110 --client_id 1  --venv_activate=/root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/venv/bin/activate 