#!/bin/bash

export CERTIFIER_PROTOTYPE=/root/certifier-framework-for-confidential-computing
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app

cd $EXAMPLE_DIR

# Cold init
echo "[*] Running cold-init"
$EXAMPLE_DIR/example_app.exe \
  --data_dir=./app1_data/ \
  --operation=cold-init \
  --measurement_file="example_app.measurement" \
  --policy_store_file=policy_store \
  --print_all=true \
  "$@"

# # Get certified
echo "[*] Running get-certified"
$EXAMPLE_DIR/example_app.exe \
  --data_dir=./app1_data/ \
  --operation=get-certified \
  --measurement_file="example_app.measurement" \
  --policy_store_file=policy_store \
  --print_all=true \
  "$@"


# # Run as client
echo "[*] Running app as client"
$EXAMPLE_DIR/example_app.exe \
  --data_dir=./app1_data/ \
  --operation=run-app-as-client \
  --policy_store_file=policy_store \
  --print_all=true \
  --workdir=/root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/ \
  --client_script=/root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/federated/binary/client.py \
  --venv_path=/root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/venv/bin/activate \
  "$@"

# docker run -it --name ve3c-server --network certifier-net -p 8123:8123 -p 8124:8124 ve3c-image server --host=0.0.0.0
# docker run -it --name ve3c-client --network certifier-net ve3c-image client

# ./run_client.sh \
#  --fl_workdir /root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/ \
#  --server_app_host 0.0.0.0 \
#  -- policy_host 0.0.0.0 \
#  --client_script /root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/federated/binary/client.py \
#  --client_id 1 \
#  --venv_activate /root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/venv/bin/activate 

#  docker run --name ccfl-client --network ccfl-net \
#   ccfl:latest client \
#   --server_app_host=0.0.0.0 \
#   --policy_host=0.0.0.0 \
#   --client_script=client.py \
#   --venv_activate=/root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/venv/bin/activate \
#   --client_id=1