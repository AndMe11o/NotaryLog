import os
import sys
import traceback

if "TPM2TOOLS_TCTI" not in os.environ:
    os.environ["TPM2TOOLS_TCTI"] = "swtpm:port=2321"

try:
    from eth_account import Account
    import tpm2_pytss
    from tpm2_pytss import ESAPI
    from tpm2_pytss.types import (
        TPM2B_PUBLIC,
        TPMT_PUBLIC,
        TPMA_OBJECT,
        TPMI_ALG_HASH,
        TPMU_PUBLIC_PARMS,
        TPMS_ECC_PARMS,
        TPMT_SYM_DEF_OBJECT,
        TPMT_ECC_SCHEME,
        TPMI_ECC_CURVE,
        TPMS_ECC_POINT,
        TPM2B_ECC_PARAMETER,
        TPM2B_SENSITIVE,
        TPMT_SENSITIVE,
        TPMU_SENSITIVE_COMPOSITE,
    )
except Exception as e:
    print(f"[-] Errore di import dettagliato: {e}")
    traceback.print_exc()
    sys.exit(1)

PERSISTENT_HANDLE = 0x81010002
TPM2_RH_OWNER = 0x40000001
TPM2_ECC_SECP256K1 = 0x0017  # ID curva secp256k1

def import_eth_key_to_tpm(raw_hex_key: str):
    clean_key = raw_hex_key.strip()
    if clean_key.startswith("0x"):
        clean_key = clean_key[2:]

    if len(clean_key) != 64:
        raise ValueError(f"Lunghezza chiave non valida: attesi 64 caratteri, trovati {len(clean_key)}")

    priv_bytes = bytes.fromhex(clean_key)
    acct = Account.from_key("0x" + clean_key)
    print(f"[*] Indirizzo Ethereum associato: {acct.address}")

    pub_key_bytes = bytes(acct._key_obj.public_key.to_bytes())
    pub_x = pub_key_bytes[:32]
    pub_y = pub_key_bytes[32:]

    with ESAPI(tcti=os.environ.get("TPM2TOOLS_TCTI")) as ectx:
        # 1. Rilascia l'handle se già occupato in NVRAM
        try:
            ectx.evict_control(
                auth=TPM2_RH_OWNER,
                object_handle=PERSISTENT_HANDLE,
                persistent_handle=PERSISTENT_HANDLE,
            )
            print(f"[!] Handle precedente {hex(PERSISTENT_HANDLE)} liberato.")
        except Exception:
            pass

        # 2. Definizione dell'area pubblica
        in_public = TPM2B_PUBLIC(
            publicArea=TPMT_PUBLIC(
                type=0x0023,  # TPM2_ALG_ECC
                nameAlg=TPMI_ALG_HASH(0x000B),  # SHA256
                objectAttributes=(
                    TPMA_OBJECT.SIGN_ENCRYPT
                    | TPMA_OBJECT.USERWITHAUTH
                    | TPMA_OBJECT.NO_DA
                ),
                parameters=TPMU_PUBLIC_PARMS(
                    eccDetail=TPMS_ECC_PARMS(
                        symmetric=TPMT_SYM_DEF_OBJECT(algorithm=0x0010),  # NULL
                        scheme=TPMT_ECC_SCHEME(
                            scheme=0x0018, details=TPMI_ALG_HASH(0x000B)  # ECDSA SHA256
                        ),
                        curveID=TPMI_ECC_CURVE(TPM2_ECC_SECP256K1),
                        kdf=dict(scheme=0x0010),
                    )
                ),
                unique=TPMS_ECC_POINT(
                    x=TPM2B_ECC_PARAMETER(pub_x),
                    y=TPM2B_ECC_PARAMETER(pub_y)
                ),
            )
        )

        # 3. Definizione dell'area sensibile (chiave privata)
        in_sensitive = TPM2B_SENSITIVE(
            sensitiveArea=TPMT_SENSITIVE(
                sensitiveType=0x0023,  # TPM2_ALG_ECC
                authValue=b"",
                seedValue=b"",
                sensitive=TPMU_SENSITIVE_COMPOSITE(
                    ecc=TPM2B_ECC_PARAMETER(priv_bytes)
                ),
            )
        )

        print("[*] Caricamento della chiave nell'emulatore TPM...")
        loaded_handle = ectx.load_external(
            in_private=in_sensitive,
            in_public=in_public,
            hierarchy=TPM2_RH_OWNER
        )

        print(f"[*] Persistenza in NVRAM all'handle {hex(PERSISTENT_HANDLE)}...")
        ectx.evict_control(
            auth=TPM2_RH_OWNER,
            object_handle=loaded_handle,
            persistent_handle=PERSISTENT_HANDLE,
        )

        ectx.flush_context(loaded_handle)

        print(f"\n[+] SUCCESSO: Chiave importata con successo nel TPM.")
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
        print("[*] Trovata HOST_PRIVATE_KEY nel file .env")
    else:
        key = input("Incolla HOST_PRIVATE_KEY: ").strip()

    import_eth_key_to_tpm(key)