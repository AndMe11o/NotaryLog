import os
import csv
import math
import time
import json
import uuid
import random
from eth_utils import keccak
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ================= COSTANTI DEL MODELLO ECONOMICO (ARBITRUM L2) =================
# Gas medio empirico per recordBatchRoot(string, bytes32, uint256)
GAS_PER_TX = 85000
# Base fee tipica su Arbitrum L2 (0.02 gwei) + priority fee (0.05 gwei)
GAS_PRICE_GWEI = 0.07
ETH_PRICE_USD = 3000.0

# Motore AES-256-GCM con chiave effimera di benchmark
AES_ENGINE = AESGCM(os.urandom(32))

# ================= PRIMITIVE CRITTOGRAFICHE IDENTICHE A BTMP_AGENT =================
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

def process_batch_payload(records: list, seq_num: int, prev_hash: str) -> tuple[float, int, float]:
    """
    Esegue realmente costruzione Merkle Tree, cifratura AES-GCM e serializzazione JSON.
    Restituisce: (cpu_time_ms, json_size_bytes, avg_proof_len)
    """
    t0 = time.perf_counter()

    batch_id = str(uuid.uuid4())
    leaves = [hash_leaf(r["raw_log"]) for r in records]
    tree = build_merkle_tree(leaves)
    root_hex = "0x" + tree[-1][0].hex()

    archive_entries = []
    total_proof_len = 0
    for idx, r in enumerate(records):
        proof = generate_proof(idx, tree)
        total_proof_len += len(proof)
        archive_entries.append({
            "id": str(uuid.uuid4()),
            "sequence_num": seq_num,
            "prev_batch_hash": prev_hash,
            "merkle_root": root_hex,
            "timestamp": r["ts"],
            "encrypted": encrypt_log(r["raw_log"]),
            "leaf": "0x" + leaves[idx].hex(),
            "batch_id": batch_id,
            "proof": proof
        })

    envelope = {
        "sequence_num": seq_num,
        "batch_id": batch_id,
        "prev_batch_hash": prev_hash,
        "merkle_root": root_hex,
        "logs": archive_entries
    }
    serialized = json.dumps(envelope, indent=2)

    cpu_ms = (time.perf_counter() - t0) * 1000.0
    return cpu_ms, len(serialized.encode("utf-8")), (total_proof_len / len(records))

# ================= GENERATORE FLUSSI DI TRAFFIC0 (10 MINUTI = 600s) =================
def generate_traffic_scenarios(seed: int = 42) -> dict:
    rng = random.Random(seed)
    scenarios = {}

    # 1. Traffico Basso / Quiete (~1 evento ogni 20s su 600s)
    idle_events = []
    t = 0.0
    while t < 600.0:
        t += rng.expovariate(1.0 / 20.0)
        if t < 600.0:
            idle_events.append({"ts": t, "raw_log": f"SUCCESS_LOGIN user='admin' tty='pts/0' rhost='10.0.0.5' pid=1234 epoch={int(1794910000+t)}"})
    scenarios["A_Traffico_Basso (0.05 log/s)"] = idle_events

    # 2. Attacco Brute-Force Sostenuto (15 log/s su 600s = ~9000 eventi)
    bf_events = []
    t = 0.0
    while t < 600.0:
        t += rng.expovariate(15.0)
        if t < 600.0:
            bf_events.append({"ts": t, "raw_log": f"FAILED_LOGIN user='root' tty='ssh' rhost='185.220.101.{rng.randint(1,254)}' pid={rng.randint(2000,9000)} epoch={int(1794910000+t)}"})
    scenarios["B_BruteForce_SSH (15 log/s)"] = bf_events

    # 3. Traffico Misto: 240s quiete -> 120s attacco (20 log/s) -> 240s quiete
    mixed_events = []
    t = 0.0
    while t < 600.0:
        rate = 20.0 if (240.0 <= t <= 360.0) else 0.05
        t += rng.expovariate(rate)
        if t < 600.0:
            label = "FAILED_LOGIN" if rate > 1.0 else "SUCCESS_LOGIN"
            mixed_events.append({"ts": t, "raw_log": f"{label} user='root' tty='ssh' rhost='91.240.118.44' pid=4412 epoch={int(1794910000+t)}"})
    scenarios["C_Traffico_Misto (Quiete+Picco)"] = mixed_events

    return scenarios

# ================= MOTORE DI SIMULAZIONE POLICY =================
def run_simulation(events: list, mode: str, **params) -> dict:
    buffer = []
    first_ts = None

    tx_count = 0
    latencies = []
    total_cpu_ms = 0.0
    total_storage_bytes = 0
    proof_lengths = []
    batch_sizes = []

    def flush(flush_time: float):
        nonlocal buffer, first_ts, tx_count, total_cpu_ms, total_storage_bytes
        if not buffer:
            return
        tx_count += 1
        batch_sizes.append(len(buffer))
        for ev in buffer:
            latencies.append(max(0.0, flush_time - ev["ts"]))

        cpu_ms, size_b, avg_p = process_batch_payload(buffer, tx_count, "0x" + "0" * 64)
        total_cpu_ms += cpu_ms
        total_storage_bytes += size_b
        proof_lengths.append(avg_p)

        buffer = []
        first_ts = None

    for ev in events:
        now = ev["ts"]

        # Controllo timeout prima di accodare il nuovo evento
        if buffer and (now - first_ts) >= params["t_max"]:
            flush(first_ts + params["t_max"])

        if not buffer:
            first_ts = now
        buffer.append(ev)

        if mode == "static":
            target_n = params["n_fixed"]
        elif mode == "adaptive":
            if len(buffer) == 1:
                target_n = params["n_min"]
            else:
                elapsed = max(now - first_ts, 0.05)
                lambda_hat = (len(buffer) - 1) / elapsed
                raw_n = math.ceil(lambda_hat * params["t_target"])
                target_n = max(params["n_min"], min(params["n_max"], raw_n))

        if len(buffer) >= target_n:
            flush(now)

    # Flush finale a fine finestra di simulazione (t = 600s)
    if buffer:
        flush(max(600.0, buffer[-1]["ts"]))

    total_gas = tx_count * GAS_PER_TX
    cost_eth = (total_gas * GAS_PRICE_GWEI) / 1e9
    cost_usd = cost_eth * ETH_PRICE_USD

    return {
        "eventi_totali": len(events),
        "tx_onchain": tx_count,
        "batch_medio": round(sum(batch_sizes) / len(batch_sizes), 2) if batch_sizes else 0,
        "gas_totale": total_gas,
        "costo_usd_stimato": round(cost_usd, 5),
        "latenza_media_s": round(sum(latencies) / len(latencies), 2) if latencies else 0,
        "latenza_max_s": round(max(latencies), 2) if latencies else 0,
        "cpu_totale_ms": round(total_cpu_ms, 2),
        "storage_kb": round(total_storage_bytes / 1024.0, 2),
        "proof_len_media": round(sum(proof_lengths) / len(proof_lengths), 2) if proof_lengths else 0
    }

# ================= ESECUZIONE E REPORT =================
if __name__ == "__main__":
    scenarios = generate_traffic_scenarios()
    policies = [
        ("Static_PoC (N=2, T=60s)", "static", {"n_fixed": 2, "t_max": 60.0}),
        ("Static_Large (N=64, T=60s)", "static", {"n_fixed": 64, "t_max": 60.0}),
        ("Adaptive (N=4..128, Tt=15s)", "adaptive", {"n_min": 4, "n_max": 128, "t_target": 15.0, "t_max": 60.0}),
    ]

    csv_rows = []
    print("=" * 115)
    print(f"{'SCENARIO':<30} | {'POLICY':<27} | {'TX':>5} | {'N_AVG':>6} | {'LAT_AVG':>7} | {'LAT_MAX':>7} | {'CPU(ms)':>8} | {'DISK(KB)':>8} | {'GAS':>9}")
    print("=" * 115)

    for sc_name, ev_list in scenarios.items():
        for pol_name, mode, params in policies:
            res = run_simulation(ev_list, mode, **params)
            print(
                f"{sc_name:<30} | {pol_name:<27} | {res['tx_onchain']:>5} | {res['batch_medio']:>6} | "
                f"{res['latenza_media_s']:>6}s | {res['latenza_max_s']:>6}s | {res['cpu_totale_ms']:>8} | "
                f"{res['storage_kb']:>8} | {res['gas_totale']:>9}"
            )
            csv_rows.append({"scenario": sc_name, "policy": pol_name, **res})
        print("-" * 115)

    csv_path = "thesis_benchmark_results.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(csv_rows[0].keys()))
        writer.writeheader()
        writer.writerows(csv_rows)

    print(f"\n[*] Risultati completi salvati in '{csv_path}' (pronti per grafici Excel/LaTeX).")