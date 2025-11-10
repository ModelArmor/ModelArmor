# Secure Federated Learning 

This directory extends the Certifier Framework for Confidential Computing to run Federated Learning (FL) with attestation, admission control, secure channels, per-client provisioning, and runtime ACLs. We currently use the simulated enclave path (no special hardware required), but the design is compatible with real TEEs (SGX/Gramine, AMD SEV, etc.).

## Ports used
1. 8123 -- Certifier Policy Service (Go simpleserver)
2. 8124 -- Example app's authenticated channel (TLS) for control, logs, provisioning
3. 8080 -- Python Flower FL server (plain HTTP) launched by the trusted server app

## What this folder contains
Everything from the upstream Certifier Framework needed to build the service and `example app`.

### The FL code and scripts:
The `sample_apps/simple_app/example_app.cc` is extended to support:
- Client handshake (HELLO id=`<N>`), composite identity = `<measured_peer_id>`|client-`<N>`
- Hot-reload ACLs (`--acl_allow_file`, `--acl_deny_file`)
- Per-client provisioning of Python files with SHA-256 integrity check
- Secure log streaming from clients over the authenticated channel
- Background launch of the Python FL server while keeping 8124 open

### Top-level helper scripts (kept one level above this folder):
- **./start_certifier_service** -- one-time build + policy setup
- **./run_server.sh** -- attests, admits, launches policy service + trusted app (server role)
- **./run_client.sh** -- attests, admits, connects to trusted app (client role)

### The FL metrics sinks at repo root: 
`secured_metrics/` and `unsecured_metrics/` each with   `client_1.csv` ... `client_10.csv` and `server_rounds.csv`.

## Security model
1. **Measurement & Policy:** We measure the trusted binary of `example_app.exe` and embed a policy that trusts that measurement and the platform's attestation key.
2. **Attestation & Admission:** Each process (`run-app-as-server` / `run-app-as-client`) attests to the policy service on 8123 and obtains an admissions cert.
- **Secure channel:** The client connects to the server on 8124 using the Certifier authenticated channel (TLS with mutual proof).
- **Runtime authorization (ACL):** The server checks composite identity Measured-`<hash>`|client-`<id>` against allow/deny lists (hot-reloaded).
- **Provisioning (optional)**: The server selectively sends a Python file to a client (provision.map → client-`<id>`=/path/to/file.py).
- **Protocol:** PROVISION `<fname>` `<size>`
`<sha256>` followed by raw bytes.
- Client validates SHA-256 and writes to `--provision_dir`.

## FL execution:
1. Server launches Flower (Python) on 8080 in the background (keeps 8124 alive).
2. Client launches Python client.py (dataset shard, metrics, RSS) and streams logs to the server over 8124.
3. Files we touch the most `sample_apps/simple_app/example_app.cc` (server & client logic)

## Key additions:
1. **Handshake:** client sends HELLO id=`<client_id>`; server forms `composite = sanitize(<peer_id>) + "|" + <logical_id>`.
2. **ACL:**
    - `--acl_allow_file`, `--acl_deny_file` (newline-separated entries, e.g., Measured-...\|client-3)
    - Hot-reload via file mtime checks; enforced before and during a session.
3. **Provisioning:** server reads --provision_map (e.g.,   `client-1=/root/.../client1.py`). Sends file with header + bytes + SHA-256; client acknowledges (PROVISION-OK) or errors.

## On server:
nohup + setsid + disown to launch `server.py` in background, writing to `server.log`.

## On client: 
launches `client.py` with flags and streams logs over the
secure channel.

## Why keep 8124 open?
- The authenticated channel is the control/log pipe.
- FL runs independently on 8080; the TLS channel must not be blocked by the FL loop. 
- Backgrounding the Python server fixes that.

## One-time setup
Run this from the repo root (scripts are in the parent of this directory):

### 1) Build, generate keys, embed policy, measure binary, sign claims, package policy, build servers
```
./start_certifier_service
```
#### What it does:
1. Cleans sample artifacts, builds utilities, creates a fresh `provisioning/` dir.
2. Generates policy, platform, attest keys; embeds the policy cert into `policy_key.cc`.
3. Compiles example_app.exe and produces a measurement.
4. Builds VSE claims (trusted for attestation/trusted measurement), signs, and packages into policy.bin.
5. Builds Go policy service (`certifier_service/simpleserver`) and supporting libs.
6. Creates per-client data dirs `app1_data` ... `app11_data` and seeds them with provisioning outputs.
7. Copies `policy.bin` and related files into
`sample_apps/simple_app/service/`.

### 2) Running the secure FL server
 On the server VM 
```
./run_server.sh\
--host=0.0.0.0\
--policy_host=0.0.0.0\
--server_app_host=0.0.0.0\
--workdir=/root/non-secure-federated-learning\
--server_script=/root/non-secure-federated-learning/server.py\
--venv_path=/opt/venv/bin/activate
```

#### What happens:
1. Starts the policy service (`simpleserver`) on 8123 with `policy.bin`.
2. Runs `example_app.exe` in server role: cold-init → get-certified → run-app-as-server.
3. Background-launches the Python FL server (server.py) on 8080, logs → server.log.
4. Listens on 8124 for FL clients: ACL checks (allow/deny files if provided) Provisioning based on --provision_map (optional)
5. Receives line-buffered logs and round markers from clients
6. Configure per-client provisioning with a mapping file (e.g., `sample_apps/simple_app/provision.map`)
    ```
    client-1=/root/non-secure-federated-learning/client_overrides/client1.py
    client-5=/root/non-secure-federated-learning/client_overrides/client5.py
    ```
7. Pass it to the server via:
    ```
    --provision_map=/root/secure-federated-learning/sample_apps/simple_app/provision.map
    ```

### 3) Running a secure FL client \#
 On each client VM (set client_id
appropriately) 
```
./run_client.sh\
--policy_host=`<SERVER_IP>`{=html}\
--server_app_host=`<SERVER_IP>`{=html}\
--client_id=3\
--workdir=/root/non-secure-federated-learning\
--client_script=/root/non-secure-federated-learning/client.py\
--venv_path=/root/venv/bin/activate\
--provision_dir=/root/secure-federated-learning/sample_apps/simple_app/TrainedFilters/\
--provision_accept=true
```

#### What happens:
1. `example_app.exe` runs in client role: cold-init → get-certified →
run-app-as-client.
2. Connects to server on 8124, handshakes (HELLO id=X), waits for
provisioning (if any).
3. Launches Python client.py (Flower) in --workdir, passing server
address/dataset flags.
4. Streams logs and \[ROUND\] markers to the server over the authenticated
channel.
5. With --auto_data_dir_per_client=true, the client's data root becomes `./app<id>data/`.

## Important flags

1. ### ACLs:
- `--acl_allow_file=/path/allow.txt`
- `--acl_deny_file=/path/deny.txt`

    Entries are Measured-`<hash>`|client-`<id>`{=html}; hot-reloaded on change.

2. ### Provisioning:
- Server: `--provision_map=/path/provision.map`
- Client: `--provision_accept=true`, `--provision_dir=/path/to/save`

3. ### Python runner
- Server: `--workdir`, `--server_script`, `--venv_path`
- Client: `--workdir`, `--client_script`, `--venv_path`

4. ### Policy/Service endpoints
- `--policy_host`, `--policy_port` (default 8123)
- `--server_app_host`, `--server_app_port` (default 8124)

## How simulated enclaves fit in

We set enclave_type = "`simulated-enclave`" and supply three parameters to the Certifier:
1. Attest key (`attest_key_file.bin`)
2. Measurement (`example_app.measurement`)
3. Platform endorsement (`platform_attest_endorsement.bin`)

The policy states that the platform key trusts the attest key for attestation.
1. The policy key trusts the measurement of our app.
2. On `cold-init` the app records algorithms, endpoints, and policy into its `policy store`.
3. On `get-certified` it proves its identity to 8123 and receives an admissions certificate.
4. The authenticated channel on 8124 is then established using the Certifier's TLS wrapper.

## Switching to a real TEE (e.g., SGX/Gramine or AMD SEV) mostly means:
1. Building the appropriate \*\_SIMPLE_APP target
2. Swapping enclave parameter loading
3. Regenerating measurements and updating policy

## Metrics & artifacts
1. **Secure run outputs: place per-client CSVs under `secured_metrics/`:**
- `client_1.csv` ... `client_10.csv`(columns:
round,duration_s,peak_rss_mb,notes)
- server_rounds.csv for aggregator timings

2. **Baseline (non-secure) outputs:** `unsecured_metrics/` with the same layout

These folders power the plotting scripts (*training time* and *peak RSS* for *secured vs. unsecured*).

## Troubleshooting
1. Client connects but does nothing:

    Check server 8124 is up; verify ACL allows
    Measured-...\|client-`<id>`.

2. If provisioning is expected, confirm the entry exists in `provision.map` and the file is readable.

3. 8124 drops when FL starts:
    Ensure you're using the background launch path in `example_app.cc` (nohup/setsid/disown). The trusted channel must remain open while `server.py` runs on 8080.
4. Policy errors
    - Re-run `./start_certifier_service` to rebuild *keys/policy/measurement* and copy artifacts into the right places.

## Quick reference (what each script does)
1. ### ./start_certifier_service:

    Build certifier utilities, generate keys/certs, embed policy, compile app, measure app, sign VSE claims, package policy.bin, build Go simpleserver, create per-client app\*\_data roots and seed with provisioning artifacts.

2. ### ./run_server.sh:

    Start `simpleserver` on 8123, then `example_app.exe` (server role) to: cold-init → get-certified → run-app-as-server. Background-launch Python FL server on 8080; keep 8124 open for `control/logs/provisioning`.

3. ### ./run_client.sh:
    `example_app.exe` (client role) to: cold-init → get-certified → run-app-as-client. Accept provisioning (if enabled), run Python FL client, stream logs via 8124.
