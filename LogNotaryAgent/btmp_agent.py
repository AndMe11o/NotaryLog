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
ENV_PATH = os.path.join(BASE_DIR, ".env")

TPM_NVRAM_KEY_INDEX = "0x1500018"
TPM_NVRAM_AES_INDEX = "0x1500019"
TPM2TOOLS_TCTI = "swtpm:port=2321"

BATCH_SIZE = 2
HEARTBEAT_TIMEOUT = 60

# RICORDA: Inserisci qui l'indirizzo del tuo wallet Host registrato sulla DApp
EXPECTED_ADDRESS = Web3.to_checksum_address("0x24b6998117C0568d3A263ba509Ab14c87773ec81")

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

# ================= PARSER BINARIO UTMP (BTMP + WTMP) =================
# Struct utmp Linux x86_64 (384 bytes):
# [0] ut_type (h), [1] ut_pid (i), [2] ut_line (32s), [3] ut_id (4s),
# [4] ut_user (32s), [5] ut_host (256s), [6] e_termination (h), [7] e_exit (h),
# [8] ut_session (i), [9] ut_tv.tv_sec (i), [10] ut_tv.tv_usec (i), [11..14] ut_addr_v6 (4i), [15] reserved (20s)
UTMP_STRUCT_FORMAT = "hi32s4s32s256shhiii4i20s"
RECORD_SIZE = struct.calcsize(UTMP_STRUCT_FORMAT)  # 384 bytes
USER_PROCESS = 7  # Sessione utente autenticata in <utmp.h>

def parse_utmp_record(raw_bytes: bytes, event_label: str, only_user_process: bool = False):
    if len(raw_bytes) < RECORD_SIZE:
        return None
    fields = struct.unpack(UTMP_STRUCT_FORMAT, raw_bytes)
    ut_type = fields[0]
    ut_pid = fields[1]
    ut_line = fields[2].split(b'\0', 1)[0].decode('latin1', errors='replace').strip()
    ut_user = fields[4].split(b'\0', 1)[0].decode('latin1', errors='replace').strip()
    ut_host = fields[5].split(b'\0', 1)[0].decode('latin1', errors='replace').strip()

    # Estrazione corretta di tv_sec (indice 9 su x86_64) con fallback su indice 8 o time.time()
    ut_tv_sec = fields[9] if fields[9] > 1000000000 else fields[8]
    if ut_tv_sec <= 1000000000 or ut_tv_sec > 4102444800:
        ut_tv_sec = int(time.time())

    # Per wtmp filtriamo solo i veri login utente (ignorando reboot, dead_process, runlevel)
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
            # Gestione logrotate (cambio inode)
            if st.st_ino != self.inode:
                print(f"[*] Rilevata rotazione log su {self.path}. Riapertura file...")
                self.file.close()
                self.file = open(self.path, "rb")
                self.inode = st.st_ino
            # Gestione copytruncate (file rimpicciolito)
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
            # Scrittura parziale in corso da parte di PAM/sshd: attendi il prossimo ciclo
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

# ================= ANCORAGGIO ON-CHAIN E SALVATAGGIO GERARCHICO =================
def anchor_batch(batch_records: list):
    if not batch_records:
        return

    batch_id = str(uuid.uuid4())
    leaves = [hash_leaf(r["raw_log"]) for r in batch_records]
    tree = build_merkle_tree(leaves)
    root_bytes = tree[-1][0]
    root_hex = "0x" + root_bytes.hex()

    print(f"\n[ANCHOR] Invio Batch {batch_id} ({len(batch_records)} eventi) | Root: {root_hex}")

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

    # Ricostruzione effimera della chiave privata: vive solo in questo blocco
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
        # Formattazione con orario locale leggibile dall'epoch reale dell'evento
        readable_ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["epoch"]))
        archive_entries.append({
            "id": str(uuid.uuid4()),
            "timestamp": readable_ts,
            "encrypted": encrypt_log(r["raw_log"]),
            "leaf": "0x" + leaves[idx].hex(),
            "batch_id": batch_id,
            "proof": generate_proof(idx, tree),
            "tx_hash": tx_hash.hex()
        })

    # Creazione struttura gerarchica: archives / YYYY-MM / YYYY-MM-DD / batch_<batch_id>.json
    now_local = time.localtime()
    month_folder = time.strftime("%Y-%m", now_local)
    day_folder = time.strftime("%Y-%m-%d", now_local)

    target_dir = os.path.join(ARCHIVES_BASE_DIR, month_folder, day_folder)
    os.makedirs(target_dir, exist_ok=True)

    batch_filename = f"batch_{batch_id}.json"
    batch_file_path = os.path.join(target_dir, batch_filename)

    with open(batch_file_path, "w") as f:
        json.dump(archive_entries, f, indent=2)

    print(f"[ARCHIVE] {len(archive_entries)} record cifrati salvati in: {batch_file_path}\n")

# ================= LOOP PRINCIPALE =================
if __name__ == "__main__":
    btmp_reader = UtmpStreamReader(BTMP_PATH, "FAILED_LOGIN", only_user_process=False)
    wtmp_reader = UtmpStreamReader(WTMP_PATH, "SUCCESS_LOGIN", only_user_process=True)

    print(f"[*] Monitoraggio attivo su {BTMP_PATH} (Falliti) e {WTMP_PATH} (Riusciti)...")
    print(f"[*] Directory archivi strutturati: {ARCHIVES_BASE_DIR}/<YYYY-MM>/<YYYY-MM-DD>/batch_<id>.json")

    buffer = []
    last_flush = time.time()

    while True:
        # Controlla login falliti (btmp)
        rec_fail = btmp_reader.read_next()
        if rec_fail:
            buffer.append(rec_fail)
            print(f"[INGEST - FAIL] ({len(buffer)}/{BATCH_SIZE}) {rec_fail['raw_log']}")

        # Controlla login riusciti (wtmp)
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