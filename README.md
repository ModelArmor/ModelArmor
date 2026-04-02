# ModelArmor

## What problem are we solving?
Modern ML enthusiast want to use **Federated Learning (FL)** to keep raw data local while training a shared model. But two practical questions still block adoption:

1. **Security & trust**: How do we know a participating node (client or server) is legitimate, runs the expected code, and communicates over a protected channel at any cloud or edge platform?
2. **Cost of security**: If we add protections such as attestation, policy checks, secure runtime, what overhead do we pay in training time and memory compared to a normal, non-secure FL deployment?

## What is ModelArmor?
**ModelArmor** is an easy to deploy and implement testbed that runs the FL workload in two modes and compares them:

- **Non-Secure FL (baseline)** — standard VMs running a Flower server and several clients.
- **Secure FL (SFL)** — the same workload launched through a trust loop using **simulated enclaves** representing a  confidential computing continnum, and including admission via certificates, per-peer identity, Access Control List (ACL) gating, and an authenticated control channel for optional per-client provisioning such that server can send a file/config to a specific client at connect time.

Both modes produce the same metrics so we can do apples-to-apples evaluation.

## How does ModelArmor solve it?
- **Keep our FL code**: We do not change the core FL training logic. Instead, we wrap startup with a minimal “trust manager” that performs:
  - **Cold-init** → generate keys & policy store  
  - **Get-certified** → obtain admission from a policy service  
  - **Run-as-server/client** → establish an authenticated, encrypted channel; verify identities; (optionally) provision per-client files
- **Simulated enclaves**: We use simulated enclaves to introduce **confidential computing concepts** (measured identity, protected channel, policy checks) without requiring enclave-specific coding.
- **Tight, comparable metrics**: Each client logs per-round training time and peak RSS (MB); the server logs aggregation time. We run 100 rounds with 10 clients in both modes and store results in structured CSVs for direct comparison.
- **Operator controls**: Simple allow/deny ACLs using the peer’s measured identity + logical client ID; optional **per-client provisioning** via the secure channel (e.g., “send this file to client-5 at connect”).

## What did we build as FL test workload?
- A Flower-based FL workload (MNIST + lightweight CNN) wired for consistent per-round metrics.
- A **non-secure path** (plain VMs) and a **secure path** (simulated enclaves + certification + ACL + provisioning) that both run the same training.
<!-- - A clean **metrics layout**:
  - `unsecured_metrics/client_1.csv … client_10.csv`, `unsecured_metrics/server_rounds.csv`
  - `secured_metrics/client_1.csv … client_10.csv`, `secured_metrics/server_rounds.csv`
- A plotting script to compare **training time** and **memory** across modes (per-client, aggregate, and server aggregation). -->

## What questions can we answer with ModelArmor?
- **How much slower (if at all)** does secure FL run vs non-secure for our workload and hardware?
- **Does memory usage change** meaningfully under the secure path?
- **What is the variability** (by round, by client) and where are the outliers?
- **What policies** (ACL, provisioning) matter for operational control without destabilizing training?

## Why this matters
ModelArmor gives us a repeatable method to quantify the operational cost of adding confidential-computing-style protections to FL—without changing out model code. We can make evidence-based tradeoffs: keep privacy and integrity guarantees while knowing the runtime and memory impact on their actual workload.

## Where to find details
- **Non-Secure FL**: see [non-secure-federated-learning/README.md](non-secure-federated-learning/README.md)
- **Secure FL (SFL)**: see [secure-federated-learning/README.md](secure-federated-learning/README.md)
- **Appendix**: see [appendix.pdf](appendix.pdf)

<!-- - **Figures**: run `make_figures.py` to generate comparisons in `figures/` -->

## Next steps
- Swap in our own dataset/model to test different compute/memory profiles.  
- Turn simulated enclaves into **hardware TEEs** when available.  
- Extend metrics (e.g., network I/O, CPU time, energy) and add fault/attack drills (data poisoning, rogue clients) gated by policy.
