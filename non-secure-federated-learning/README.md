# Non-Secure Federated Learning (Baseline)

This folder contains the **baseline FL setup** (no attestation/ACL/secure channel).
It uses a lightweight CNN on MNIST with Flower: one **aggregation server** and **10 clients** training on **pre-sharded** local datasets.  
Outputs are round-by-round **training time** and **peak RSS (MB)** per client, plus **server aggregation** timings.


## Quick start

### 1) Python env
```
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -r requirements.txt
```
### 2) Create data shards
```
# By default makes 10 IID shards under ./shards/
python prepare_shards.py --num_clients 10 --out_dir ./shards
```
### What it does
- Downloads MNIST (once, into ./data/).
- Flattens/normalizes samples.
- Saves each client’s train/test arrays into ./shards/client_<id>/{train_X.npy,train_y.npy,test_X.npy,test_y.npy}.

We can change count/output via:
```
python prepare_shards.py --num_clients 5 --out_dir ./shards_small
```
### 3) Start the FL server
```
# Runs on 0.0.0.0:8080 by default, logs metrics to ./metrics_server/server_rounds.csv
python server.py --host 0.0.0.0 --port 8080 --rounds 100
```
### 4) Start clients (one per machine/terminal)
Example for client 1:

```
python client.py \
  --server http://<SERVER_IP>:8080 \
  --client_id 1 \
  --shard_dir ./shards \
  --local_epochs 1
```
Spin up clients 2..n similarly (set --client_id accordingly).
Each client writes ./metrics/client_\<id>\.csv with:
```
round,duration_s,peak_rss_mb,notes
1,0.8123,588.7,acc=...,loss=...
...
```
Tip: If shards live elsewhere, pass --shard_dir /path/to/shards.

## Command-line flags
### server.py
-  --host (str, default 0.0.0.0)
- --port (int, default 8080)
- --rounds (int, default 100) – global rounds
- --metrics_dir (str, default ./metrics_server) – writes server_rounds.csv

### client.py
- --server (str, required) – e.g., http://127.0.0.1:8080
- --client_id (int, required) – 1..N
- --shard_dir (str, default ./shards)
- --local_epochs (int, default 1)
- --batch_size (int, default 64)
- --metrics_dir (str, default ./metrics)
- --device (str, default cpu) – set cuda if available

## What the model looks like
A compact CNN suitable for MNIST:

Conv → ReLU → Conv → ReLU → MaxPool → Dropout → Dense → ReLU → Dropout → Dense(10)

Optimizer: SGD or Adam (config in client.py)

Loss: CrossEntropy

Client trains locally for --local_epochs and returns weights to Flower.

## Metrics collected
### Clients (./metrics/client_\<id>\.csv)
- round – global round index
- duration_s – wall-clock time for local train+eval in that round (seconds)
- peak_rss_mb – max resident set size during the round (MB)
- notes – short text (e.g., acc=0.978 loss=0.073)

### Server (./metrics_server/server_rounds.csv)
- round – global round index
- duration_s – server aggregation duration (seconds)
- (optionally) clients_selected, agg_time_s, timestamps

All timings are already in seconds; no conversion needed for plotting.

## Reproducing a n-client run
### On the server VM:
```
source venv/bin/activate
python server.py --host 0.0.0.0 --port 8080 --rounds 100
```
### On each client VM (IDs 1..n):
```
source venv/bin/activate
# copy or mount the same shards/ layout, or run prepare_shards.py once then distribute
python client.py --server http://<SERVER_IP>:8080 --client_id <ID> --shard_dir ./shards --local_epochs 1
```
### Collect artifacts:
- Clients: metrics/client_<id>.csv
- Server: metrics_server/server_rounds.csv

## Troubleshooting
Client hangs on connect
Ensure the server is reachable on <SERVER_IP>:8080 and security groups/firewall allow inbound 8080 on the server and outbound from clients.

## “Shard not found”
Confirm ./shards/client_<id>/train_X.npy exists on that VM; pass --shard_dir if using a custom path.