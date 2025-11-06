# server.py
# Flower FedAvg server with round timing logs. Works on CPU-only t2.medium.
import os, time, csv, pathlib
import flwr as fl
from flwr.server.strategy import FedAvg
from flwr.server import ServerConfig

ROUNDS = int(os.environ.get("ROUNDS", "100"))
MIN_FIT = int(os.environ.get("MIN_FIT", "10"))        # require all 10 clients by default
MIN_AVAIL = int(os.environ.get("MIN_AVAIL", "10"))
FRACTION_FIT = float(os.environ.get("FRACTION_FIT", "1.0"))
SERVER_ADDR = os.environ.get("SERVER_ADDR", "0.0.0.0:8080")
METRICS_DIR = os.environ.get("METRICS_DIR", "metrics_server")

pathlib.Path(METRICS_DIR).mkdir(parents=True, exist_ok=True)
ROUND_CSV = os.path.join(METRICS_DIR, "server_rounds.csv")

# Round timing helper
_round_times = {}

def on_fit_config_fn(server_round: int):
    # send small config to clients
    return {
        "server_round": server_round,
        "local_epochs": int(os.environ.get("LOCAL_EPOCHS", "1")),
        "batch_size": int(os.environ.get("BATCH", "32")),
        "lr": float(os.environ.get("LR", "0.01")),
        "seed": int(os.environ.get("SEED", "42")),
    }

def record_round_start(r: int):
    _round_times[r] = {"start": time.time()}

def record_round_end(r: int, num_clients_selected: int, agg_time_s: float):
    t = _round_times.get(r, {})
    start = t.get("start", time.time())
    end = time.time()
    dur = end - start
    t.update({"end": end, "duration_s": dur, "clients": num_clients_selected, "agg_time_s": agg_time_s})
    _round_times[r] = t
    write_round_row(r, t)

def write_round_row(r: int, tdict: dict):
    header = ["round","duration_s","clients_selected","agg_time_s","start_ts","end_ts"]
    file_exists = os.path.exists(ROUND_CSV)
    with open(ROUND_CSV, "a", newline="") as f:
        w = csv.writer(f)
        if not file_exists:
            w.writerow(header)
        w.writerow([
            r,
            round(tdict.get("duration_s", 0.0), 4),
            tdict.get("clients", 0),
            round(tdict.get("agg_time_s", 0.0), 4),
            int(tdict.get("start", time.time())),
            int(tdict.get("end", time.time())),
        ])

# Wrap strategy to capture aggregation timing
class TimedFedAvg(FedAvg):
    def aggregate_fit(self, server_round, results, failures):
        agg_t0 = time.time()
        record_round_start(server_round)
        agg_res = super().aggregate_fit(server_round, results, failures)
        agg_t1 = time.time()
        record_round_end(server_round, num_clients_selected=len(results), agg_time_s=(agg_t1-agg_t0))
        return agg_res

def main():
    strategy = TimedFedAvg(
        fraction_fit=FRACTION_FIT,
        min_fit_clients=MIN_FIT,
        min_available_clients=MIN_AVAIL,
        on_fit_config_fn=on_fit_config_fn,
    )

    print(f"[server] Starting at {SERVER_ADDR} with {ROUNDS} rounds")
    fl.server.start_server(
        server_address=SERVER_ADDR,
        strategy=strategy,
        config=ServerConfig(num_rounds=ROUNDS),
    )

if __name__ == "__main__":
    main()
