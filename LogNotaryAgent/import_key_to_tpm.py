import os
import sys

if "TPM2TOOLS_TCTI" not in os.environ:
    os.environ["TPM2TOOLS_TCTI"] = "swtpm:port=2321"

try:
    from eth_account import Account
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend

    from tpm2_pytss import ESAPI
    from tpm2_pytss.constants import (
        TPM2_RH,
        TPM2_ALG,
        TPMA_OBJECT,
    )
    from tpm2_pytss.types import (
        TPM2B_PUBLIC,
        TPM2B_SENSITIVE,
    )
except Exception as e:
    print(f"[-] Errore caricamento librerie: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

PERSISTENT_HANDLE = 0x81010002

def import_eth_key_to_tpm(raw_hex_key: str):
    clean_key = raw_hex_key.strip()
    if clean_key.startswith("0x"):
        clean_key = clean_key[2:]

    if len(clean_key) != 64:
        raise ValueError(f"Lunghezza chiave non valida: attesi 64 caratteri esadecimali, trovati {len(clean_key)}")

    priv_int = int(clean_key, 16)
    acct = Account.from_key("0x" + clean_key)
    print(f"[*] Indirizzo Ethereum calcolato: {acct.address}")

    # 1. Ricostruzione oggetto secp256k1 via cryptography
    priv_key_obj = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())

    # 2. Conversione diretta nelle strutture TPM2B supportata nativamente da tpm2-pytss
    in_public, in_sensitive = TPM2B_PUBLIC.from_crypto(
        priv_key_obj,
        name_alg=TPM2_ALG.SHA256,
        object_attributes=(
            TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.NO_DA
        ),
    )

    with ESAPI(tcti=os.environ.get("TPM2TOOLS_TCTI")) as ectx:
        # 3. Libera l'handle NVRAM se precedentemente occupato
        try:
            ectx.evict_control(
                auth=TPM2_RH.OWNER,
                object_handle=PERSISTENT_HANDLE,
                persistent_handle=PERSISTENT_HANDLE,
            )
            print(f"[!] Handle precedente {hex(PERSISTENT_HANDLE)} rimosso.")
        except Exception:
            pass

        # 4. Carica la chiave nell'emulatore
        print("[*] Caricamento chiave nel TPM...")
        loaded_handle = ectx.load_external(
            in_private=in_sensitive,
            in_public=in_public,
            hierarchy=TPM2_RH.OWNER,
        )

        # 5. Salva in memoria persistente NVRAM
        print(f"[*] Salvataggio persistente nell'NVRAM all'handle {hex(PERSISTENT_HANDLE)}...")
        ectx.evict_control(
            auth=TPM2_RH.OWNER,
            object_handle=loaded_handle,
            persistent_handle=PERSISTENT_HANDLE,
        )

        ectx.flush_context(loaded_handle)

        print("\n[+] SUCCESSO: Chiave blindata nell'NVRAM del TPM!")
        print(f"[+] Handle persistente: {hex(PERSISTENT_HANDLE)}")
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