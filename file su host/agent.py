import os
import time
import json
import uuid
import struct
from web3 import Web3
from eth_account import Account
from eth_utils import keccak

# ================= CONFIGURAZIONE =================
RPC_URL = "https://sepolia-rollup.arbitrum.io/rpc"
CHAIN_ID = 421614
CONTRACT_ADDRESS = "0x95847671fD4c9aCca5C83F0b4cA570fd1de9F056"
BTMP_PATH = "/var/log/btmp"
ARCHIVE_PATH = "/home/LogNotaryAgent/audit_archive.json"
ENV_PATH = "/home/LogNotaryAgent/.env"

# Valori di default
PRIVATE_KEY = None
BATCH_SIZE = 2  # Impostato a 2 per vedere subito il batch con due login errati
HEARTBEAT_TIMEOUT = 60

# Parsing del file .env esistente
if os.path.exists(ENV_PATH):
    with open(ENV_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k in ("HOST_PRIVATE_KEY", "PRIVATE_KEY"):
                    PRIVATE_KEY = v
                elif k == "RPC_URL":
                    RPC_URL = v
                elif k == "CONTRACT_ADDRESS":
                    CONTRACT_ADDRESS = v
                elif k == "BATCH_TIMEOUT_SECONDS":
                    try:
                        HEARTBEAT_TIMEOUT = int(v)
                    except ValueError:
                        pass

if not PRIVATE_KEY:
    raise ValueError("HOST_PRIVATE_KEY non trovata nel file .env")

CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "string", "name": "_batchId", "type": "string"},
            {"internalType": "bytes32", "name": "_merkleRoot", "type": "bytes32"},
            {"internalType": "uint256", "name": "_logCount", "type": "uint256"}
        ],
        "name": "recordBatchRoot",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = Account.from_key(PRIVATE_KEY)
contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=CONTRACT_ABI)

print(f"[*] LogNotary BTMP Agent avviato per: {account.address}")
print(f"[*] Batch size: {BATCH_SIZE} record | Heartbeat timeout: {HEARTBEAT_TIMEOUT}s")

# ================= PARSER BINARIO UTMP (x86_64: 384 bytes) =================
UTMP_STRUCT_FORMAT = "hi32s4s32s256shhiii4i20s"
RECORD_SIZE = struct.calcsize(UTMP_STRUCT_FORMAT)

def parse_btmp_record(raw_bytes):
    if len(raw_bytes) < RECORD_SIZE:
        return None
    fields = struct.unpack(UTMP_STRUCT_FORMAT, raw_bytes)
    ut_pid = fields[1]
    ut_line = fields[2].split(b'\0', 1)[0].decode('latin1', errors='replace')
    ut_user = fields[4].split(b'\0', 1)[0].decode('latin1', errors='replace')
    ut_host = fields[5].split(b'\0', 1)[0].decode('latin1', errors='replace')
    ut_tv_sec = fields[8]

    if not ut_user and not ut_host:
        return None

    formatted_entry = f"FAILED_LOGIN user='{ut_user}' tty='{ut_line}' rhost='{ut_host}' pid={ut_pid} epoch={ut_tv_sec}"
    return {
        "raw_log": formatted_entry,
        "epoch": ut_tv_sec
    }

# ================= MERKLE ENGINE =================
def hash_leaf(log_str):
    return keccak(text=log_str)

def combine_hashes(a, b):
    return keccak(a + b) if a <= b else keccak(b + a)

def build_merkle_tree(leaves):
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

def generate_proof(index, layers):
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

# ================= ANCORAGGIO ON-CHAIN =================
def anchor_batch(batch_records):
    if not batch_records:
        return

    batch_id = str(uuid.uuid4())
    leaves = [hash_leaf(r["raw_log"]) for r in batch_records]
    tree = build_merkle_tree(leaves)
    root_bytes = tree[-1][0]
    root_hex = "0x" + root_bytes.hex()

    print(f"\n[ANCHOR] Batch {batch_id} con {len(batch_records)} record.")
    print(f"         Root: {root_hex}")

    nonce = w3.eth.get_transaction_count(account.address, 'pending')
    fee_data = w3.eth.fee_history(1, 'latest')
    base_fee = fee_data['baseFeePerGas'][-1]
    max_priority = w3.to_wei(0.05, 'gwei')
    max_fee = int(base_fee * 1.5) + max_priority

    tx = contract.functions.recordBatchRoot(
        batch_id,
        root_bytes,
        len(batch_records)
    ).build_transaction({
        'from': account.address,
        'nonce': nonce,
        'maxFeePerGas': max_fee,
        'maxPriorityFeePerGas': max_priority,
        'chainId': CHAIN_ID
    })

    try:
        tx['gas'] = int(w3.eth.estimate_gas(tx) * 1.2)
    except Exception:
        tx['gas'] = 350000

    signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"[TX SENT] Hash: {tx_hash.hex()} - In attesa di Arbitrum Sepolia...")
    w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"[SUCCESS] Root confermata nel blocco L2.")

    archive_entries = []
    for idx, r in enumerate(batch_records):
        proof = generate_proof(idx, tree)
        archive_entries.append({
            "id": str(uuid.uuid4()),
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(r["epoch"])),
            "raw_log": r["raw_log"],
            "leaf": "0x" + leaves[idx].hex(),
            "batch_id": batch_id,
            "proof": proof,
            "tx_hash": tx_hash.hex()
        })

    existing = []
    if os.path.exists(ARCHIVE_PATH):
        try:
            with open(ARCHIVE_PATH, "r") as f:
                existing = json.load(f)
                if not isinstance(existing, list):
                    existing = [existing]
        except Exception:
            existing = []

    existing.extend(archive_entries)
    with open(ARCHIVE_PATH, "w") as f:
        json.dump(existing, f, indent=2)
    print(f"[ARCHIVE] {len(archive_entries)} record aggiunti a {ARCHIVE_PATH}\n")

# ================= LOOP DI ASCOLTO =================
buffer = []
last_flush = time.time()

with open(BTMP_PATH, "rb") as f:
    f.seek(0, os.SEEK_END)
    print(f"[*] In ascolto su {BTMP_PATH}...")

    while True:
        chunk = f.read(RECORD_SIZE)
        if chunk and len(chunk) == RECORD_SIZE:
            record = parse_btmp_record(chunk)
            if record:
                buffer.append(record)
                print(f"[INGEST] ({len(buffer)}/{BATCH_SIZE}) {record['raw_log']}")

        now = time.time()
        if len(buffer) >= BATCH_SIZE or (buffer and (now - last_flush) >= HEARTBEAT_TIMEOUT):
            anchor_batch(buffer)
            buffer = []
            last_flush = time.time()

        time.sleep(0.5)