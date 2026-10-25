#!/usr/bin/env python3
import os
import sys
import json
import time
import uuid
import re
import subprocess
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Any
from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account

# Carica configurazioni da .env
load_dotenv()

RPC_URL = os.getenv("RPC_URL", "https://sepolia-rollup.arbitrum.io/rpc")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
HOST_PRIVATE_KEY = os.getenv("HOST_PRIVATE_KEY")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))
BATCH_TIMEOUT_SECONDS = int(os.getenv("BATCH_TIMEOUT_SECONDS", "900"))
ARCHIVE_FILE_PATH = os.getenv("ARCHIVE_FILE_PATH", "audit_archive.json")

if not CONTRACT_ADDRESS or not HOST_PRIVATE_KEY:
    print("[FATAL] CONTRACT_ADDRESS o HOST_PRIVATE_KEY mancanti nel file .env")
    sys.exit(1)

# Inizializza Web3 e Account
w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print(f"[FATAL] Impossibile connettersi all'RPC: {RPC_URL}")
    sys.exit(1)

account = Account.from_key(HOST_PRIVATE_KEY)
CONTRACT_ADDRESS = Web3.to_checksum_address(CONTRACT_ADDRESS)

# ABI minima per la funzione recordBatchRoot
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

contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)


# ==========================================
# CRITTOGRAFIA: MERKLE TREE (OPENZEPPELIN COMPATIBLE)
# ==========================================

def hash_leaf(data: str) -> bytes:
    """Calcola la foglia di Merkle: keccak256(data)."""
    return w3.keccak(text=data)

def combine_hashes(a: bytes, b: bytes) -> bytes:
    """
    Combina due nodi in modo compatibile con OpenZeppelin MerkleProof.sol:
    a e b vengono ordinati lessicograficamente prima dell'hashing.
    """
    if a <= b:
        return w3.keccak(a + b)
    else:
        return w3.keccak(b + a)

def build_merkle_tree(leaves: List[bytes]) -> Tuple[bytes, List[List[bytes]]]:
    """
    Costruisce l'albero di Merkle binario.
    Restituisce la (merkle_root, livelli_dell_albero).
    """
    if not leaves:
        empty_root = w3.keccak(b"")
        return empty_root, []

    layers = [leaves]
    current = leaves

    while len(current) > 1:
        next_layer = []
        for i in range(0, len(current), 2):
            left = current[i]
            if i + 1 < len(current):
                right = current[i + 1]
            else:
                # Se il livello è dispari, duplica l'ultimo nodo
                right = left
            next_layer.append(combine_hashes(left, right))
        layers.append(next_layer)
        current = next_layer

    return current[0], layers

def generate_proof_for_index(index: int, layers: List[List[bytes]]) -> List[str]:
    """
    Estrae l'array di proof per la foglia all'indice specificato.
    """
    proof = []
    curr_idx = index
    for layer in layers[:-1]:
        is_right_child = (curr_idx % 2 == 1)
        pair_idx = curr_idx - 1 if is_right_child else curr_idx + 1
        if pair_idx < len(layer):
            proof.append("0x" + layer[pair_idx].hex())
        else:
            # Nodo duplicato a fine livello dispari
            proof.append("0x" + layer[curr_idx].hex())
        curr_idx = curr_idx // 2
    return proof


# ==========================================
# GESTIONE TRANSAZIONI ARBITRUM L2 (EIP-1559)
# ==========================================

def send_anchor_transaction(batch_id: str, merkle_root_bytes: bytes, log_count: int, max_retries: int = 5) -> str:
    """
    Invia la transazione recordBatchRoot su Arbitrum Sepolia gestendo
    nonce 'pending', gas buffer L2 e retry con backoff esponenziale.
    """
    for attempt in range(1, max_retries + 1):
        try:
            # Recupera nonce sullo stato 'pending' per evitare nonce collisions
            nonce = w3.eth.get_transaction_count(account.address, "pending")

            # Calcolo tariffe EIP-1559 ottimizzate per L2
            latest_block = w3.eth.get_block("latest")
            base_fee = latest_block.get("baseFeePerGas", w3.to_wei("0.1", "gwei"))
            priority_fee = w3.eth.max_priority_fee or w3.to_wei("0.05", "gwei")

            # Margine x2.5 sulla baseFee per assorbire picchi di traffico sul sequencer L2
            max_fee = int(base_fee * 2.5) + priority_fee

            # Stima del gas limit
            tx_data = contract.functions.recordBatchRoot(
                batch_id,
                merkle_root_bytes,
                log_count
            )
            estimated_gas = tx_data.estimate_gas({"from": account.address})
            gas_limit = int(estimated_gas * 1.3)

            tx_params = {
                "chainId": 421614,  # Arbitrum Sepolia
                "nonce": nonce,
                "from": account.address,
                "maxFeePerGas": max_fee,
                "maxPriorityFeePerGas": priority_fee,
                "gas": gas_limit
            }

            raw_tx = tx_data.build_transaction(tx_params)
            signed_tx = w3.eth.account.sign_transaction(raw_tx, private_key=HOST_PRIVATE_KEY)

            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            tx_hash_hex = "0x" + tx_hash.hex()
            print(f"[L2] Transazione inviata: {tx_hash_hex} (Tentativo {attempt})")

            # Attesa conferma
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            if receipt.status == 1:
                print(f"[L2] Batch {batch_id} confermato nel blocco #{receipt.blockNumber} (Gas Used: {receipt.gasUsed})")
                return tx_hash_hex
            else:
                raise Exception("Transazione revertata on-chain.")

        except Exception as e:
            print(f"[WARN] Errore invio transazione ({attempt}/{max_retries}): {str(e)}")
            if attempt == max_retries:
                raise e
            backoff = 2 ** attempt
            time.sleep(backoff)


# ==========================================
# ARCHIVIAZIONE FORENSE LOCALE
# ==========================================

def append_to_archive(records: List[Dict[str, Any]]):
    """
    Appende i record validati a un array JSON integro e permanente.
    """
    archive_data = []
    if os.path.exists(ARCHIVE_FILE_PATH):
        try:
            with open(ARCHIVE_FILE_PATH, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    archive_data = json.loads(content)
                    if not isinstance(archive_data, list):
                        archive_data = [archive_data]
        except Exception as e:
            print(f"[WARN] Ripristino archivio corrotto: {e}")
            archive_data = []

    archive_data.extend(records)

    with open(ARCHIVE_FILE_PATH, "w", encoding="utf-8") as f:
        json.dump(archive_data, f, indent=2, ensure_ascii=False)
    print(f"[ARCHIVE] {len(records)} record salvati in {ARCHIVE_FILE_PATH}")


# ==========================================
# FLUSH E ANCORAGGIO BATCH
# ==========================================

def flush_batch(log_buffer: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Prende i log nel buffer, calcola il Merkle Tree, invia la Root on-chain
    e salva i record con i relativi proof in audit_archive.json.
    """
    if not log_buffer:
        return []

    batch_id = str(uuid.uuid4())
    log_count = len(log_buffer)
    print(f"\n[BATCH] Avvio elaborazione Batch {batch_id} con {log_count} log...")

    leaves = [item["leaf_bytes"] for item in log_buffer]
    merkle_root_bytes, layers = build_merkle_tree(leaves)
    merkle_root_hex = "0x" + merkle_root_bytes.hex()
    print(f"[MERKLE] Root calcolata: {merkle_root_hex}")

    # Ancoraggio su Arbitrum Sepolia
    tx_hash = send_anchor_transaction(batch_id, merkle_root_bytes, log_count)

    # Arricchisce i record con il Merkle Proof
    completed_records = []
    for idx, item in enumerate(log_buffer):
        proof = generate_proof_for_index(idx, layers)
        completed_records.append({
            "id": item["id"],
            "timestamp": item["timestamp"],
            "raw_log": item["raw_log"],
            "leaf": "0x" + item["leaf_bytes"].hex(),
            "batch_id": batch_id,
            "merkle_root": merkle_root_hex,
            "proof": proof,
            "tx_hash": tx_hash
        })

    append_to_archive(completed_records)
    return []


# ==========================================
# PIPELINE DI INGESTION (JOURNALCTL)
# ==========================================

SSH_PATTERNS = re.compile(r"(Failed password|Accepted|Invalid user|authentication failure|session opened|session closed)", re.IGNORECASE)

def start_daemon():
    print("=" * 60)
    print(f"LogNotary Host Agent avviato per: {account.address}")
    print(f"Smart Contract L2: {CONTRACT_ADDRESS}")
    print(f"Soglia Batch: {BATCH_SIZE} log | Timeout Heartbeat: {BATCH_TIMEOUT_SECONDS}s")
    print("=" * 60)

    # Identifica il servizio SSH su Ubuntu (ssh o sshd)
    service_name = "ssh"
    journal_cmd = ["journalctl", "-u", service_name, "-f", "-n", "0", "--output=cat"]

    proc = subprocess.Popen(
        journal_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    # Mette stdout in non-blocking per consentire il controllo del timeout
    os.set_blocking(proc.stdout.fileno(), False)

    log_buffer: List[Dict[str, Any]] = []
    last_flush_time = time.time()

    try:
        while True:
            line = proc.stdout.readline()
            now = time.time()

            if line:
                line_str = line.strip()
                # Filtra solo gli eventi di sicurezza SSH rilevanti
                if SSH_PATTERNS.search(line_str):
                    log_id = str(uuid.uuid4())
                    leaf_bytes = hash_leaf(line_str)
                    
                    log_buffer.append({
                        "id": log_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "raw_log": line_str,
                        "leaf_bytes": leaf_bytes
                    })
                    print(f"[INGEST] ({len(log_buffer)}/{BATCH_SIZE}) {line_str[:70]}...")

            # Condizione 1: Raggiunta la dimensione massima del batch
            if len(log_buffer) >= BATCH_SIZE:
                print(f"[TRIGGER] Raggiunta soglia di {BATCH_SIZE} log.")
                log_buffer = flush_batch(log_buffer)
                last_flush_time = time.time()

            # Condizione 2: Raggiunto il timeout temporale (15 minuti)
            elif (now - last_flush_time) >= BATCH_TIMEOUT_SECONDS:
                print("[TRIGGER] Raggiunta soglia temporale.")
                
                # Anti-Silent Failure: se vuoto, crea un log sintetico di Heartbeat
                if len(log_buffer) == 0:
                    hb_msg = json.dumps({
                        "event": "HEARTBEAT",
                        "status": "ALIVE",
                        "host": account.address,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    print("[HEARTBEAT] Nessun log rilevato: generato evento sintetico di heartbeat.")
                    log_buffer.append({
                        "id": str(uuid.uuid4()),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "raw_log": hb_msg,
                        "leaf_bytes": hash_leaf(hb_msg)
                    })

                log_buffer = flush_batch(log_buffer)
                last_flush_time = time.time()

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[STOP] Arresto operatore. Salvataggio log residui...")
        if log_buffer:
            flush_batch(log_buffer)
        proc.terminate()
        sys.exit(0)

if __name__ == "__main__":
    start_daemon()
