# client.py
# Minimal, CPU-only Flower client for MNIST shards with per-round timing & peak RSS logging.

import os, time, pathlib, csv, psutil, argparse
import torch, torch.nn as nn, torch.nn.functional as F
from torch.utils.data import DataLoader, Subset
from torchvision import datasets, transforms
import numpy as np
import flwr as fl
from typing import Tuple, List

# ------------------------
# CLI ARGUMENTS
# ------------------------
parser = argparse.ArgumentParser(description="Federated Learning Client for MNIST")
parser.add_argument("-i", "--id", type=int, help="Client ID", default=int(os.environ.get("CLIENT_ID", 1)))
parser.add_argument("-a", "--addr", type=str, help="Server address (e.g., 127.0.0.1:8080)", default=os.environ.get("SERVER_ADDR", "127.0.0.1:8080"))
parser.add_argument("-d", "--datasets", type=str, help="Server address (e.g., 127.0.0.1:8080)", default=os.environ.get("SERVER_ADDR", "127.0.0.1:8080"))
args = parser.parse_args()

# ------------------------
# ENV / defaults
# ------------------------
CLIENT_ID = args.id
SERVER_ADDR = args.addr+":8080"
SHARD_DIR = os.environ.get("SHARD_DIR", "shards")
BATCH = int(os.environ.get("BATCH", "32"))
LOCAL_EPOCHS = int(os.environ.get("LOCAL_EPOCHS", "1"))
LR = float(os.environ.get("LR", "0.01"))
SEED = int(os.environ.get("SEED", "42"))
NUM_WORKERS = int(os.environ.get("NUM_WORKERS", "0"))
METRICS_DIR = os.environ.get("METRICS_DIR", "metrics")

pathlib.Path(METRICS_DIR).mkdir(parents=True, exist_ok=True)
CSV_PATH = os.path.join(METRICS_DIR, f"client_{CLIENT_ID}.csv")

torch.manual_seed(SEED)
np.random.seed(SEED)
device = torch.device("cpu")  # t2.micro friendly

# ------------------------
# Data
# ------------------------
def load_dataloaders() -> Tuple[DataLoader, DataLoader]:
    tr = transforms.Compose([transforms.ToTensor()])
    ds_train = datasets.MNIST(root="data/mnist", train=True, download=True, transform=tr)
    shard_path = os.path.join(SHARD_DIR, f"client_{CLIENT_ID}.npy")
    idx = np.load(shard_path)
    ds_train = Subset(ds_train, indices=idx)
    ds_test = datasets.MNIST(root="data/mnist", train=False, download=True, transform=tr)
    train_loader = DataLoader(ds_train, batch_size=BATCH, shuffle=True, num_workers=NUM_WORKERS)
    test_loader = DataLoader(ds_test, batch_size=256, shuffle=False, num_workers=NUM_WORKERS)
    return train_loader, test_loader

# ------------------------
# Model
# ------------------------
class TinyMLP(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc1 = nn.Linear(28*28, 128)
        self.fc2 = nn.Linear(128, 10)
    def forward(self, x):
        x = x.view(x.size(0), -1)
        x = F.relu(self.fc1(x))
        x = self.fc2(x)
        return x

def get_parameters(model: nn.Module) -> List[np.ndarray]:
    return [p.detach().cpu().numpy() for p in model.parameters()]

def set_parameters(model: nn.Module, params: List[np.ndarray]) -> None:
    with torch.no_grad():
        for p, nd in zip(model.parameters(), params):
            p.set_(torch.tensor(nd))

# ------------------------
# Metrics logging
# ------------------------
def mem_rss_mb() -> float:
    return psutil.Process(os.getpid()).memory_info().rss / (1024*1024)

def log_client_metrics(round_id: int, duration_s: float, note: str = ""):
    file_exists = os.path.exists(CSV_PATH)
    with open(CSV_PATH, "a", newline="") as f:
        w = csv.writer(f)
        if not file_exists:
            w.writerow(["round", "duration_s", "peak_rss_mb", "notes"])
        w.writerow([round_id, round(duration_s,4), round(mem_rss_mb(),2), note])

# ------------------------
# Train / Eval
# ------------------------
def train_one_round(model, loader, epochs: int, lr: float):
    model.train()
    opt = torch.optim.SGD(model.parameters(), lr=lr, momentum=0.9)
    crit = nn.CrossEntropyLoss()
    for _ in range(epochs):
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            opt.zero_grad()
            logits = model(xb)
            loss = crit(logits, yb)
            loss.backward()
            opt.step()

def test(model, loader):
    model.eval()
    correct, total, loss_sum = 0, 0, 0.0
    crit = nn.CrossEntropyLoss(reduction="sum")
    with torch.no_grad():
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            logits = model(xb)
            loss_sum += crit(logits, yb).item()
            pred = logits.argmax(dim=1)
            correct += (pred == yb).sum().item()
            total += yb.size(0)
    return loss_sum/total, correct/total

# ------------------------
# Flower Client
# ------------------------
class MnistClient(fl.client.NumPyClient):
    def __init__(self):
        self.model = TinyMLP().to(device)
        self.train_loader, self.test_loader = load_dataloaders()
    def get_parameters(self, config):
        return get_parameters(self.model)
    def fit(self, parameters, config):
        set_parameters(self.model, parameters)
        rnd = int(config.get("server_round", 0))
        local_epochs = int(config.get("local_epochs", LOCAL_EPOCHS))
        lr = float(config.get("lr", LR))
        t0 = time.time()
        train_one_round(self.model, self.train_loader, epochs=local_epochs, lr=lr)
        dur = time.time() - t0
        loss, acc = test(self.model, self.test_loader)
        log_client_metrics(rnd, dur, note=f"acc={round(acc,4)} loss={round(loss,4)}")
        return get_parameters(self.model), len(self.train_loader.dataset), {}
    def evaluate(self, parameters, config):
        set_parameters(self.model, parameters)
        loss, acc = test(self.model, self.test_loader)
        return float(loss), len(self.test_loader.dataset), {"accuracy": float(acc)}

# ------------------------
def main():
    print(f"[client {CLIENT_ID}] connecting to {SERVER_ADDR}")
    fl.client.start_numpy_client(server_address=SERVER_ADDR, client=MnistClient())

if __name__ == "__main__":
    main()
