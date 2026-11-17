import os
import csv
import math
import time
import json
import uuid
import struct
import signal
from eth_utils import keccak
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BTMP_PATH = "/var/log/btmp"
UTMP_STRUCT_FORMAT = "hi32s4s32s256shhiii4i20s"
RECORD_SIZE = struct.calcsize(UTMP_STRUCT_FORMAT)  # 384 bytes

GAS_PER_TX = 85000
GAS_PRICE_GWEI = 0.07
ETH_PRICE_USD = 3000.0
AES_ENGINE = AESGCM(os.urandom(32))

# ================= PRIMITIVE CRITTOGRAFICHE =================
def hash_leaf(log_str: str) -> bytes:
    return keccak(text=log_str)

def combine_hashes(a: bytes, b: bytes) -> bytes:
    return keccak(a + b) if a <= b else keccak(b + a)

def build_merkle_tree(leaves: list) -> list:
    layers = [leaves]
    current = leaves
    while len(current) > 1:
        next_layer = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if (i + 1) < len(current) else current[i]
            next_layer.append(combine_hashes(left, right))
        layers.append(next_layer)
        current = next_layer
    return layers

def generate_proof(index: int, layers: list) -> list:
    proof = []
    for l in range(len(layers) - 1):
        layer = layers[l]
        is_right = (index % 2 == 1)
        pair_index = (index - 1) if is_right else (index + 1)
        if pair_index < len(layer):
            proof.append("0x" + layer[pair_index].hex())
        else:
            proof.append("0x" + layer[index].hex())
        index = index // 2
    return proof

def encrypt_log(raw_text: str) -> dict:
    nonce = os.urandom(12)
    encrypted_data = AES_ENGINE.encrypt(nonce, raw_text.encode("utf-8"), None)
    return {
        "ciphertext": encrypted_data[:-16].hex(),
        "nonce": nonce.hex(),
        "tag": encrypted_data[-16:].hex()
    }

# ================= SIMULATORE POLICY IN PARALLELO =================
class PolicyTracker:
    def __init__(self, name: str, mode: str, **params):
        self.name = name
        self.mode = mode
        self.params = params
        self.buffer = []
        self.first_ts = None

        self.tx_count = 0
        self.batch_sizes = []
        self.latencies = []
        self.total_cpu_ms = 0.0
        self.total_storage_bytes = 0
        self.proof_lengths = []

    def ingest(self, event: dict, now: float):
        if not self.buffer:
            self.first_ts = now
        self.buffer.append(event)

        if self.mode == "static":
            target_n = self.params["n_fixed"]
        else:
            if len(self.buffer) == 1:
                target_n = self.params["n_min"]
            else:
                elapsed = max(now - self.first_ts, 0.05)
                lambda_hat = (len(self.buffer) - 1) / elapsed
                raw_n = math.ceil(lambda_hat * self.params["t_target"])
                target_n = max(self.params["n_min"], min(self.params["n_max"], raw_n))

        if len(self.buffer) >= target_n:
            self.flush(now)

    def check_timeout(self, now: float):
        if self.buffer and (now - self.first_ts) >= self.params["t_max"]:
            self.flush(now)

    def flush(self, now: float):
        if not self.buffer:
            return
        t0 = time.perf_counter()

        self.tx_count += 1
        self.batch_sizes.append(len(self.buffer))
        for ev in self.buffer:
            self.latencies.append(max(0.0, now - ev["arrival_ts"]))

        batch_id = str(uuid.uuid4())
        leaves = [hash_leaf(r["raw_log"]) for r in self.buffer]
        tree = build_merkle_tree(leaves)
        root_hex = "0x" + tree[-1][0].hex()

        entries = []
        proof_sum = 0
        for idx, r in enumerate(self.buffer):
            p = generate_proof(idx, tree)
            proof_sum += len(p)
            entries.append({
                "id": str(uuid.uuid4()),
                "sequence_num": self.tx_count,
                "merkle_root": root_hex,
                "encrypted": encrypt_log(r["raw_log"]),
                "leaf": "0x" + leaves[idx].hex(),
                "batch_id": batch_id,
                "proof": p
            })

        payload_json = json.dumps({"batch_id": batch_id, "merkle_root": root_hex, "logs": entries}, indent=2)
        cpu_ms = (time.perf_counter() - t0) * 1000.0

        self.total_cpu_ms += cpu_ms
        self.total_storage_bytes += len(payload_json.encode("utf-8"))
        self.proof_lengths.append(proof_sum / len(self.buffer))

        print(f"  [{self.name:<26}] FLUSH -> Batch #{self.tx_count} ({len(self.buffer)} log) | CPU: {cpu_ms:.2f}ms")
        self.buffer = []
        self.first_ts = None

    def summary(self, total_events: int) -> dict:
        total_gas = self.tx_count * GAS_PER_TX
        cost_usd = ((total_gas * GAS_PRICE_GWEI) / 1e9) * ETH_PRICE_USD
        return {
            "policy": self.name,
            "eventi_catturati": total_events,
            "tx_onchain": self.tx_count,
            "batch_medio": round(sum(self.batch_sizes) / len(self.batch_sizes), 2) if self.batch_sizes else 0,
            "latenza_media_s": round(sum(self.latencies) / len(self.latencies), 2) if self.latencies else 0,
            "latenza_max_s": round(max(self.latencies), 2) if self.latencies else 0,
            "cpu_totale_ms": round(self.total_cpu_ms, 2),
            "storage_kb": round(self.total_storage_bytes / 1024.0, 2),
            "proof_len_media": round(sum(self.proof_lengths) / len(self.proof_lengths), 2) if self.proof_lengths else 0,
            "gas_totale": total_gas,
            "costo_usd_stimato": round(cost_usd, 6)
        }

# ================= LOOP PRINCIPALE SU /VAR/LOG/BTMP =================
running = True
def stop_handler(sig, frame):
    global running
    running = False

signal.signal(signal.SIGINT, stop_handler)

if __name__ == "__main__":
    trackers = [
        PolicyTracker("Static_PoC (N=2, T=60s)", "static", n_fixed=2, t_max=60.0),
        PolicyTracker("Static_Large (N=64, T=60s)", "static", n_fixed=64, t_max=60.0),
        PolicyTracker("Adaptive (N=4..128, Tt=15s)", "adaptive", n_min=4, n_max=128, t_target=15.0, t_max=60.0)
    ]

    f = open(BTMP_PATH, "rb")
    f.seek(0, os.SEEK_END)
    total_events = 0

    print(f"[*] In ascolto reale su {BTMP_PATH}. Avvia lo script SSH da Windows!")
    print("[*] Premi Ctrl+C a fine test per chiudere i batch residui e generare il report CSV.\n")

    while running:
        now = time.time()
        for tr in trackers:
            tr.check_timeout(now)

        pos = f.tell()
        chunk = f.read(RECORD_SIZE)
        if not chunk or len(chunk) < RECORD_SIZE:
            f.seek(pos, os.SEEK_SET)
            time.sleep(0.1)
            continue

        fields = struct.unpack(UTMP_STRUCT_FORMAT, chunk)
        ut_pid = fields[1]
        ut_line = fields[2].split(b'\0', 1)[0].decode('latin1', errors='replace').strip()
        ut_user = fields[4].split(b'\0', 1)[0].decode('latin1', errors='replace').strip()
        ut_host = fields[5].split(b'\0', 1)[0].decode('latin1', errors='replace').strip()
        ut_tv_sec = fields[9] if fields[9] > 1000000000 else fields[8]

        if not ut_user and not ut_host:
            continue

        total_events += 1
        raw_log = f"FAILED_LOGIN user='{ut_user}' tty='{ut_line}' rhost='{ut_host}' pid={ut_pid} epoch={ut_tv_sec}"
        print(f"[SSH EVENT #{total_events}] {raw_log}")

        ev = {"arrival_ts": now, "raw_log": raw_log}
        for tr in trackers:
            tr.ingest(ev, now)

    print("\n[*] Chiusura test: flush dei buffer residui...")
    end_now = time.time()
    for tr in trackers:
        tr.flush(end_now)

    rows = [tr.summary(total_events) for tr in trackers]
    print("\n" + "=" * 110)
    print(f"{'POLICY':<28} | {'EV':>4} | {'TX':>4} | {'N_AVG':>6} | {'LAT_AVG':>7} | {'LAT_MAX':>7} | {'CPU(ms)':>8} | {'DISK(KB)':>8} | {'GAS':>8}")
    print("=" * 110)
    for r in rows:
        print(
            f"{r['policy']:<28} | {r['eventi_catturati']:>4} | {r['tx_onchain']:>4} | {r['batch_medio']:>6} | "
            f"{r['latenza_media_s']:>6}s | {r['latenza_max_s']:>6}s | {r['cpu_totale_ms']:>8} | "
            f"{r['storage_kb']:>8} | {r['gas_totale']:>8}"
        )
    print("=" * 110)

    with open("real_ssh_benchmark.csv", "w", newline="") as cf:
        writer = csv.DictWriter(cf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print("[*] Report salvato in 'real_ssh_benchmark.csv'.")