# prepare_shards.py
# Creates 10 client index files for MNIST (IID by default; Dirichlet with --alpha for non-IID).

import argparse, os, pathlib, numpy as np
from torchvision import datasets, transforms

def build_indices_iid(n_samples, n_clients):
    all_idx = np.arange(n_samples)
    np.random.shuffle(all_idx)
    return np.array_split(all_idx, n_clients)

def build_indices_dirichlet(labels, n_clients, alpha=0.3, seed=123):
    # Non-IID partitioning per label with Dirichlet(alpha)
    rng = np.random.default_rng(seed)
    n_classes = labels.max() + 1
    idx_by_class = [np.where(labels == c)[0] for c in range(n_classes)]
    client_idx = [[] for _ in range(n_clients)]
    for c in range(n_classes):
        idx_c = idx_by_class[c]
        rng.shuffle(idx_c)
        # draw proportions for this class
        props = rng.dirichlet([alpha] * n_clients)
        # turn proportions into split sizes
        sizes = (props * len(idx_c)).astype(int)
        # adjust to match total
        while sizes.sum() < len(idx_c):
            sizes[rng.integers(0, n_clients)] += 1
        splits = np.split(idx_c, np.cumsum(sizes)[:-1])
        for k in range(n_clients):
            client_idx[k].extend(splits[k])
    return [np.array(sorted(lst)) for lst in client_idx]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out_dir", default="shards", type=str)
    ap.add_argument("--n_clients", default=10, type=int)
    ap.add_argument("--non_iid", action="store_true")
    ap.add_argument("--alpha", type=float, default=0.3, help="Dirichlet alpha (smaller = more skew)")
    ap.add_argument("--seed", type=int, default=123)
    args = ap.parse_args()

    pathlib.Path(args.out_dir).mkdir(parents=True, exist_ok=True)

    # Load MNIST train set for training indices
    ds = datasets.MNIST(root="data/mnist", train=True, download=True, transform=transforms.ToTensor())
    n = len(ds)
    labels = np.array(ds.targets)

    np.random.seed(args.seed)

    if args.non_iid:
        parts = build_indices_dirichlet(labels, n_clients=args.n_clients, alpha=args.alpha, seed=args.seed)
    else:
        parts = build_indices_iid(n_samples=n, n_clients=args.n_clients)

    for i, idx in enumerate(parts, start=1):
        np.save(os.path.join(args.out_dir, f"client_{i}.npy"), idx)
    print(f"Wrote {args.n_clients} shard files to '{args.out_dir}/client_*.npy'")

if __name__ == "__main__":
    main()


# Docker download# ===== Install Docker on Ubuntu 22.04 =====
# sudo apt update && sudo apt upgrade -y

# # Install dependencies
# sudo apt install -y ca-certificates curl gnupg lsb-release

# # Add Docker’s official GPG key
# sudo mkdir -p /etc/apt/keyrings
# curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# # Add Docker’s official repository
# echo \
#   "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
#   https://download.docker.com/linux/ubuntu \
#   $(lsb_release -cs) stable" | \
#   sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# # Install Docker Engine, CLI, Containerd, Buildx, and Compose plugin
# sudo apt update
# sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# # Enable and start Docker
# sudo systemctl enable docker
# sudo systemctl start docker

# # Add current user to docker group (so you can run docker without sudo)
# sudo usermod -aG docker $USER

# # Show Docker version and test installation
# docker --version
# docker run hello-world

# echo "✅ Docker installation complete. Log out and back in (or run 'newgrp docker') to use Docker without sudo."
