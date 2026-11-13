import os
import time
import json
import uuid
import struct
import hashlib
import subprocess
from web3 import Web3
from eth_account import Account
from eth_utils import keccak
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ================= CONFIGURAZIONE =================
RPC_URL = "https://sepolia-rollup.arbitrum.io/rpc"
CHAIN_ID = 421614
CONTRACT_ADDRESS = "0x95847671fD4c9aCca5C83F0b4cA570fd1de9F056"

BTMP_PATH = "/var/log/btmp"  # Login falliti
WTMP_PATH = "/var/log/wtmp"  # Login riusciti

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ARCHIVES_BASE_DIR = os.path.join(BASE_DIR, "archives")
CHAIN_STATE_PATH = os.path.join(BASE_DIR, ".chain_state.json")
ENV_PATH = os.path.join(BASE_DIR, ".env")

TPM_NVRAM_KEY_INDEX = "0x1500018"
TPM_NVRAM_AES_INDEX = "0x1500019"
TPM2TOOLS_TCTI = "swtpm:port=2321"

BATCH_SIZE = 2
HEARTBEAT_TIMEOUT = 60


EXPECTED_ADDRESS = None

if os.path.exists(ENV_PATH):
    with open(ENV_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = [x.strip().strip('"').strip("'") for x in line.split("=", 1)]
            if k == "RPC_URL":
                RPC_URL = v
            elif k == "CONTRACT_ADDRESS":
                CONTRACT_ADDRESS = v
            elif k == "EXPECTED_ADDRESS":
                EXPECTED_ADDRESS = Web3.to_checksum_address(v)
            # ... resto delle variabili ...

if not EXPECTED_ADDRESS:
    raise SystemExit("[FATAL] EXPECTED_ADDRESS non configurato nel file .env. Arresto esecuzione.")


# Caricamento eventuali override da .env (senza chiavi in chiaro)
if os.path.exists(ENV_PATH):
    with open(ENV_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = [x.strip().strip('"').strip("'") for x in line.split("=", 1)]
            if k == "RPC_URL":
                RPC_URL = v
            elif k == "CONTRACT_ADDRESS":
                CONTRACT_ADDRESS = v
            elif k == "TPM_NVRAM_INDEX":
                TPM_NVRAM_KEY_INDEX = v
            elif k == "TPM_NVRAM_AES_INDEX":
                TPM_NVRAM_AES_INDEX = v
            elif k == "TPM2TOOLS_TCTI":
                TPM2TOOLS_TCTI = v
            elif k == "BATCH_SIZE":
                BATCH_SIZE = int(v)
            elif k == "BATCH_TIMEOUT_SECONDS":
                HEARTBEAT_TIMEOUT = int(v)

# ================= LETTURA HARDWARE TPM NVRAM =================
def read_tpm_nvram_bytes(index: str, tcti: str) -> bytes:
    env = os.environ.copy()
    env["TPM2TOOLS_TCTI"] = tcti
    res = subprocess.run(
        ["tpm2_nvread", index, "-C", "o"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )
    if res.returncode != 0:
        raise RuntimeError(f"Errore lettura TPM NVRAM ({index}): {res.stderr.decode('utf-8', errors='replace').strip()}")
    if len(res.stdout) != 32:
        raise ValueError(f"Dimensione dati TPM ({index}) non valida: attesi 32 byte, ricevuti {len(res.stdout)}")
    return res.stdout

# ================= EPHEMERAL KEY RECONSTRUCTION =================
def get_ephemeral_signing_key() -> bytes:
    """
    Ricostruisce la chiave privata EOA just-in-time tramite XOR
    tra i 32 byte nello slot TPM 0x1500018 e l'hash SHA-256 di questo file.
    """
    masked_bytes = read_tpm_nvram_bytes(TPM_NVRAM_KEY_INDEX, TPM2TOOLS_TCTI)
    with open(os.path.abspath(__file__), "rb") as f:
        code_hash = hashlib.sha256(f.read()).digest()
    return bytes(a ^ b for a, b in zip(masked_bytes, code_hash))

# Verifica di integrità all'avvio senza mantenere la chiave in RAM
_test_key = get_ephemeral_signing_key()
_derived_addr = Account.from_key(_test_key).address
del _test_key

if _derived_addr.lower() != EXPECTED_ADDRESS.lower():
    raise SystemExit(
        f"[FATAL] Violazione di integrità! Indirizzo derivato ({_derived_addr}) "
        f"diverso da quello atteso ({EXPECTED_ADDRESS}). Codice alterato o TPM non allineato."
    )

print(f"[*] Integrità codice e TPM verificata per l'account: {_derived_addr}")

print(f"[*] Inizializzazione motore AES-256-GCM da TPM ({TPM_NVRAM_AES_INDEX})...")
AES_KEY_BYTES = read_tpm_nvram_bytes(TPM_NVRAM_AES_INDEX, TPM2TOOLS_TCTI)
aesgcm_engine = AESGCM(AES_KEY_BYTES)

w3 = Web3(Web3.HTTPProvider(RPC_URL))
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
contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=CONTRACT_ABI)

# ================= GESTIONE STATO HASH CHAIN DEI BATCH =================
GENESIS_HASH = "0x" + ("0" * 64)

def load_chain_state() -> dict:
    if os.path.exists(CHAIN_STATE_PATH):
        try:
            with open(CHAIN_STATE_PATH, "r") as f:
                data = json.load(f)
                return {
                    "last_seq": int(data.get("last_seq", 0)),
                    "last_batch_hash": str(data.get("last_batch_hash", GENESIS_HASH))
                }
        except Exception as e:
            print(f"[!] Errore lettura stato catena ({e}), riparto da Genesi.")
    return {"last_seq": 0, "last_batch_hash": GENESIS_HASH}

def save_chain_state(seq_num: int, batch_hash: str):
    tmp_path = CHAIN_STATE_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump({
            "last_seq": seq_num,
            "last_batch_hash": batch_hash,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }, f, indent=2)
    os.replace(tmp_path, CHAIN_STATE_PATH)

def compute_batch_chain_hash(merkle_root_hex: str, prev_batch_hash_hex: str, batch_id: str, seq_num: int) -> str:
    """
    Calcola l'impronta di concatenazione del batch:
    keccak256(f"{merkle_root_lower}|{prev_batch_hash_lower}|{batch_id}|{seq_num}")
    """
    payload = f"{merkle_root_hex.lower()}|{prev_batch_hash_hex.lower()}|{batch_id}|{seq_num}"
    return "0x" + keccak(text=payload).hex()

# ================= PARSER BINARIO UTMP (BTMP + WTMP) =================
UTMP_STRUCT_FORMAT = "hi32s4s32s256shhiii4i20s"
RECORD_SIZE = struct.calcsize(UTMP_STRUCT_FORMAT)  # 384 bytes
USER_PROCESS = 7

def parse_utmp_record(raw_bytes: bytes, event_label: str, only_user_process: bool = False):
    if len(raw_bytes) < RECORD_SIZE:
        return None
    fields = struct.unpack(UTMP_STRUCT_FORMAT, raw_bytes)
    ut_type = fields[0]
    ut_pid = fields[1]
    ut_line = fields[2].split(b'\0', 1)[0].decode('latin1', errors='replace').strip()
    ut_user = fields[4].split(b'\0', 1)[0].decode('latin1', errors='replace').strip()
    ut_host = fields[5].split(b'\0', 1)[0].decode('latin1', errors='replace').strip()

    ut_tv_sec = fields[9] if fields[9] > 1000000000 else fields[8]
    if ut_tv_sec <= 1000000000 or ut_tv_sec > 4102444800:
        ut_tv_sec = int(time.time())

    if only_user_process and ut_type != USER_PROCESS:
        return None

    if not ut_user and not ut_host:
        return None

    formatted_entry = f"{event_label} user='{ut_user}' tty='{ut_line}' rhost='{ut_host}' pid={ut_pid} epoch={ut_tv_sec}"
    return {
        "raw_log": formatted_entry,
        "epoch": ut_tv_sec
    }

# ================= GESTIONE RESILIENTE DEI FILE LOG =================
class UtmpStreamReader:
    def __init__(self, path: str, label: str, only_user_process: bool):
        self.path = path
        self.label = label
        self.only_user_process = only_user_process
        self.file = None
        self.inode = None
        self._open_end()

    def _open_end(self):
        if not os.path.exists(self.path):
            open(self.path, "ab").close()
        self.file = open(self.path, "rb")
        self.file.seek(0, os.SEEK_END)
        self.inode = os.fstat(self.file.fileno()).st_ino

    def read_next(self):
        try:
            st = os.stat(self.path)
            if st.st_ino != self.inode:
                print(f"[*] Rilevata rotazione log su {self.path}. Riapertura file...")
                self.file.close()
                self.file = open(self.path, "rb")
                self.inode = st.st_ino
            elif st.st_size < self.file.tell():
                print(f"[*] Rilevato troncamento su {self.path}. Reset offset...")
                self.file.seek(0, os.SEEK_SET)
        except FileNotFoundError:
            return None

        pos = self.file.tell()
        chunk = self.file.read(RECORD_SIZE)
        if not chunk:
            return None
        if len(chunk) < RECORD_SIZE:
            self.file.seek(pos, os.SEEK_SET)
            return None

        return parse_utmp_record(chunk, self.label, self.only_user_process)

# ================= MOTORE MERKLE =================
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

# ================= CIFRATURA AES-256-GCM =================
def encrypt_log(raw_text: str) -> dict:
    nonce = os.urandom(12)
    encrypted_data = aesgcm_engine.encrypt(nonce, raw_text.encode("utf-8"), None)
    return {
        "ciphertext": encrypted_data[:-16].hex(),
        "nonce": nonce.hex(),
        "tag": encrypted_data[-16:].hex()
    }

# ================= ANCORAGGIO ON-CHAIN E SALVATAGGIO CONCATENATO =================
def anchor_batch(batch_records: list):
    if not batch_records:
        return

    chain_state = load_chain_state()
    seq_num = chain_state["last_seq"] + 1
    prev_batch_hash = chain_state["last_batch_hash"]

    batch_id = str(uuid.uuid4())
    leaves = [hash_leaf(r["raw_log"]) for r in batch_records]
    tree = build_merkle_tree(leaves)
    root_bytes = tree[-1][0]
    root_hex = "0x" + root_bytes.hex()

    batch_hash = compute_batch_chain_hash(root_hex, prev_batch_hash, batch_id, seq_num)

    print(f"\n[ANCHOR] Seq #{seq_num} | Batch {batch_id} ({len(batch_records)} eventi)")
    print(f"         Root: {root_hex} | PrevHash: {prev_batch_hash[:14]}... -> BatchHash: {batch_hash[:14]}...")

    nonce = w3.eth.get_transaction_count(EXPECTED_ADDRESS, "pending")
    fee_data = w3.eth.fee_history(1, "latest")
    base_fee = fee_data["baseFeePerGas"][-1]
    max_priority = w3.to_wei(0.05, "gwei")
    max_fee = int(base_fee * 1.5) + max_priority

    tx = contract.functions.recordBatchRoot(
        batch_id,
        root_bytes,
        len(batch_records)
    ).build_transaction({
        "from": EXPECTED_ADDRESS,
        "nonce": nonce,
        "maxFeePerGas": max_fee,
        "maxPriorityFeePerGas": max_priority,
        "chainId": CHAIN_ID
    })

    try:
        tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.2)
    except Exception:
        tx["gas"] = 350000

    ephemeral_key = get_ephemeral_signing_key()
    try:
        signed_tx = w3.eth.account.sign_transaction(tx, ephemeral_key)
    finally:
        del ephemeral_key

    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"[TX SENT] Hash: {tx_hash.hex()} | Attesa conferma su Arbitrum Sepolia...")
    w3.eth.wait_for_transaction_receipt(tx_hash)
    print("[SUCCESS] Merkle Root notarizzata con successo sul blocco L2.")

    archive_entries = []
    for idx, r in enumerate(batch_records):
        readable_ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["epoch"]))
        archive_entries.append({
            "id": str(uuid.uuid4()),
            "sequence_num": seq_num,
            "prev_batch_hash": prev_batch_hash,
            "batch_hash": batch_hash,
            "merkle_root": root_hex,
            "timestamp": readable_ts,
            "encrypted": encrypt_log(r["raw_log"]),
            "leaf": "0x" + leaves[idx].hex(),
            "batch_id": batch_id,
            "proof": generate_proof(idx, tree),
            "tx_hash": tx_hash.hex()
        })

    batch_envelope = {
        "sequence_num": seq_num,
        "batch_id": batch_id,
        "prev_batch_hash": prev_batch_hash,
        "merkle_root": root_hex,
        "batch_hash": batch_hash,
        "tx_hash": tx_hash.hex(),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "logs": archive_entries
    }

    now_local = time.localtime()
    month_folder = time.strftime("%Y-%m", now_local)
    day_folder = time.strftime("%Y-%m-%d", now_local)

    target_dir = os.path.join(ARCHIVES_BASE_DIR, month_folder, day_folder)
    os.makedirs(target_dir, exist_ok=True)

    batch_filename = f"seq_{seq_num:05d}_batch_{batch_id}.json"
    batch_file_path = os.path.join(target_dir, batch_filename)

    with open(batch_file_path, "w") as f:
        json.dump(batch_envelope, f, indent=2)

    save_chain_state(seq_num, batch_hash)
    print(f"[ARCHIVE] Batch #{seq_num} salvato in: {batch_file_path}\n")

# ================= LOOP PRINCIPALE =================
if __name__ == "__main__":
    btmp_reader = UtmpStreamReader(BTMP_PATH, "FAILED_LOGIN", only_user_process=False)
    wtmp_reader = UtmpStreamReader(WTMP_PATH, "SUCCESS_LOGIN", only_user_process=True)

    state = load_chain_state()
    print(f"[*] Monitoraggio attivo su {BTMP_PATH} e {WTMP_PATH}...")
    print(f"[*] Stato Hash Chain: Ultimo Seq #{state['last_seq']} | Last Hash: {state['last_batch_hash'][:18]}...")

    buffer = []
    last_flush = time.time()

    while True:
        rec_fail = btmp_reader.read_next()
        if rec_fail:
            buffer.append(rec_fail)
            print(f"[INGEST - FAIL] ({len(buffer)}/{BATCH_SIZE}) {rec_fail['raw_log']}")

        rec_succ = wtmp_reader.read_next()
        if rec_succ:
            buffer.append(rec_succ)
            print(f"[INGEST - OK]   ({len(buffer)}/{BATCH_SIZE}) {rec_succ['raw_log']}")

        now = time.time()
        if len(buffer) >= BATCH_SIZE or (buffer and (now - last_flush) >= HEARTBEAT_TIMEOUT):
            anchor_batch(buffer)
            buffer = []
            last_flush = time.time()

        if not rec_fail and not rec_succ:
            time.sleep(0.5)