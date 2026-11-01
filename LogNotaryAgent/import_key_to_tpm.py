import os
import sys
import subprocess
import tempfile
from eth_account import Account
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Configura l'accesso verso swtpm
os.environ["TPM2TOOLS_TCTI"] = os.getenv("TPM2TOOLS_TCTI", "swtpm:port=2321")
PERSISTENT_HANDLE = "0x81010002"

def run_cmd(cmd):
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Comando fallito: {' '.join(cmd)}\nStderr: {res.stderr.strip()}")
    return res.stdout.strip()

def import_eth_key_to_tpm(raw_hex_key: str):
    clean_key = raw_hex_key.strip()
    if clean_key.startswith("0x"):
        clean_key = clean_key[2:]

    if len(clean_key) != 64:
        raise ValueError(f"Lunghezza chiave non valida: attesi 64 caratteri, trovati {len(clean_key)}")

    priv_int = int(clean_key, 16)
    acct = Account.from_key("0x" + clean_key)
    print(f"[*] Indirizzo Ethereum associato: {acct.address}")

    # 1. Genera il PEM secp256k1
    priv_key_obj = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())
    pem_bytes = priv_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        pem_path = os.path.join(tmpdir, "key.pem")
        ctx_path = os.path.join(tmpdir, "key.ctx")

        with open(pem_path, "wb") as f:
            f.write(pem_bytes)

        # 2. Rilascia l'handle se già occupato
        print(f"[*] Verifica presenza handle {PERSISTENT_HANDLE}...")
        subprocess.run(
            ["tpm2_evictcontrol", "-C", "o", "-c", PERSISTENT_HANDLE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # 3. Carica la chiave nel TPM tramite tpm2_loadexternal
        print("[*] Caricamento chiave nel TPM (tpm2_loadexternal)...")
        run_cmd([
            "tpm2_loadexternal",
            "-C", "o",
            "-G", "ecc",
            "-r", pem_path,
            "-c", ctx_path
        ])

        # 4. Rendi la chiave persistente in NVRAM
        print(f"[*] Persistenza in NVRAM all'handle {PERSISTENT_HANDLE}...")
        run_cmd([
            "tpm2_evictcontrol",
            "-C", "o",
            "-c", ctx_path,
            PERSISTENT_HANDLE
        ])

    print("\n[+] SUCCESSO! Chiave blindata nell'NVRAM del TPM.")
    print(f"[+] Handle persistente: {PERSISTENT_HANDLE}")
    print(f"[+] Indirizzo verificato: {acct.address}")

if __name__ == "__main__":
    key = ""
    if os.path.exists(".env"):
        with open(".env") as f:
            for line in f:
                if line.startswith("HOST_PRIVATE_KEY="):
                    key = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break

    if key:
        print("[*] Letta HOST_PRIVATE_KEY dal file .env")
    else:
        key = input("Incolla HOST_PRIVATE_KEY: ").strip()

    import_eth_key_to_tpm(key)