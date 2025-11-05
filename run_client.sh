#!/bin/bash

export CERTIFIER_PROTOTYPE=/root/secure-federated-learning
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
  --workdir=/root/non-secure-federated-learning \
  --client_id=1 \
  --client_script=/root/secure-federated-learning/client.py \
  --venv_path=/root/venv/bin/activate \
  --auto_data_dir_per_client=true \
  --provision_dir=/root/secure-federated-learning/sample_apps/simple_app/TrainedFilters/ \
  --provision_accept=true \
  "$@"
