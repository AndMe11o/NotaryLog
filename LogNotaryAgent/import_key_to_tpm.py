import os
import sys

# Assicura che tpm2-tools e tpm2-pytss usino il socket swtpm se non impostato
if "TPM2TOOLS_TCTI" not in os.environ:
  os.environ["TPM2TOOLS_TCTI"] = "swtpm:port=2321"

try:
  from eth_account import Account
  from tpm2_pytss import (
      ESAPI,
      TPM2B_DATA,
      TPM2B_ECC_PARAMETER,
      TPM2B_PUBLIC,
      TPM2B_SENSITIVE,
      TPMA_OBJECT,
      TPMI_ALG_HASH,
      TPMI_ECC_CURVE,
      TPMS_ECC_PARMS,
      TPMS_ECC_POINT,
      TPMT_ECC_SCHEME,
      TPMT_PUBLIC,
      TPMT_SENSITIVE,
      TPMT_SYM_DEF_OBJECT,
      TPMU_PUBLIC_PARMS,
      TPMU_SENSITIVE_COMPOSITE,
  )
except ImportError:
  print("[-] Dipendenze mancanti. Esegui:")
  print("    pip install tpm2-pytss eth-account web3")
  sys.exit(1)

# Handle persistente in NVRAM (spazio standard per chiavi persistenti utente)
PERSISTENT_HANDLE = 0x81010002


def import_eth_key_to_tpm(raw_hex_key: str):
  # 1. Normalizza la chiave privata
  clean_key = raw_hex_key.strip()
  if clean_key.startswith("0x"):
    clean_key = clean_key[2:]

  if len(clean_key) != 64:
    raise ValueError(
        f"Lunghezza chiave non valida: attesi 64 caratteri esadecimali, trovati"
        f" {len(clean_key)}"
    )

  priv_bytes = bytes.fromhex(clean_key)
  acct = Account.from_key("0x" + clean_key)
  print(f"[*] Indirizzo Ethereum associato: {acct.address}")

  # Coordinate punto pubblico (x, y) sulla curva secp256k1
  pub_key_bytes = bytes(acct._key_obj.public_key.to_bytes())  # 64 bytes (X || Y)
  pub_x = pub_key_bytes[:32]
  pub_y = pub_key_bytes[32:]

  with ESAPI() as ectx:
    # 2. Controllo se l'handle è già occupato e pulizia
    try:
      print(
          f"[*] Verifica presenza handle persistente"
          f" {hex(PERSISTENT_HANDLE)}..."
      )
      ectx.evict_control(
          auth=0x40000001,  # TPM2_RH_OWNER
          object_handle=PERSISTENT_HANDLE,
          persistent_handle=PERSISTENT_HANDLE,
      )
      print(f"[!] Handle {hex(PERSISTENT_HANDLE)} liberato.")
    except Exception:
      # L'handle era già libero
      pass

    # 3. Creazione della Primary Storage Key (Parent Key nella gerarchia Owner)
    print("[*] Creazione Primary Key nel TPM...")
    primary_template = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=0x0001,  # TPM2_ALG_RSA
            nameAlg=TPMI_ALG_HASH(0x000B),  # SHA256
            objectAttributes=(
                TPMA_OBJECT.RESTRICTED
                | TPMA_OBJECT.DECRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN
                | TPMA_OBJECT.USERWITHAUTH
            ),
            parameters=TPMU_PUBLIC_PARMS(
                rsaDetail=dict(
                    symmetric=TPMT_SYM_DEF_OBJECT(
                        algorithm=0x0010, keyBits=128, mode=0x0043
                    ),  # AES-128-CFB
                    scheme=0x0010,  # NULL
                    keyBits=2048,
                    exponent=0,
                )
            ),
        )
    )

    primary_handle, _, _, _, _ = ectx.create_primary(
        primary_handle=0x40000001, in_public=primary_template
    )

    # 4. Definizione del template per la chiave ECC secp256k1
    # Costante TPM2_ECC_BN_P256 o TPM2_ECC_ECDSA_SECP256K1 (0x0017 / 23 in TPM2 spec)
    TPM2_ECC_SECP256K1 = 0x0017

    obj_attrs = (
        TPMA_OBJECT.SIGN_ENCRYPT
        | TPMA_OBJECT.USERWITHAUTH
        | TPMA_OBJECT.NO_DA  # Protezione contro dictionary attack lockout
    )

    in_public = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=0x0023,  # TPM2_ALG_ECC
            nameAlg=TPMI_ALG_HASH(0x000B),  # SHA256
            objectAttributes=obj_attrs,
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=TPMS_ECC_PARMS(
                    symmetric=TPMT_SYM_DEF_OBJECT(algorithm=0x0010),  # NULL
                    scheme=TPMT_ECC_SCHEME(
                        scheme=0x0018, details=TPMI_ALG_HASH(0x000B)
                    ),  # ECDSA SHA256
                    curveID=TPMI_ECC_CURVE(TPM2_ECC_SECP256K1),
                    kdf=dict(scheme=0x0010),
                )
            ),
            unique=TPMS_ECC_POINT(
                x=TPM2B_ECC_PARAMETER(pub_x), y=TPM2B_ECC_PARAMETER(pub_y)
            ),
        )
    )

    in_sensitive = TPM2B_SENSITIVE(
        sensitiveArea=TPMT_SENSITIVE(
            sensitiveType=0x0023,  # TPM2_ALG_ECC
            authValue=TPM2B_DATA(),
            seedValue=TPM2B_DATA(),
            sensitive=TPMU_SENSITIVE_COMPOSITE(
                ecc=TPM2B_ECC_PARAMETER(priv_bytes)
            ),
        )
    )

    # 5. Caricamento della chiave sotto la Primary Key
    print("[*] Importazione e wrapping della chiave nel TPM...")
    loaded_handle = ectx.load_external(
        in_private=in_sensitive, in_public=in_public, hierarchy=0x40000001
    )

    # 6. Salvataggio persistente in NVRAM
    print(
        f"[*] Salvataggio persistente nell'NVRAM all'handle"
        f" {hex(PERSISTENT_HANDLE)}..."
    )
    ectx.evict_control(
        auth=0x40000001,
        object_handle=loaded_handle,
        persistent_handle=PERSISTENT_HANDLE,
    )

    # Pulizia memoria volatile
    ectx.flush_context(loaded_handle)
    ectx.flush_context(primary_handle)

    print(
        f"\n[+] SUCCESSO: La chiave è ora blindata nel TPM all'indirizzo hardware"
        f" {hex(PERSISTENT_HANDLE)}."
    )
    print(
        f"[+] Puoi ora rimuovere 'PRIVATE_KEY' dal tuo file .env e lasciare"
        f" solo:\n    TPM_KEY_HANDLE={hex(PERSISTENT_HANDLE)}"
    )


if __name__ == "__main__":
  key_input = input("Incolla la tua chiave privata (0x...): ").strip()
  if not key_input:
    print("[-] Nessuna chiave inserita.")
    sys.exit(1)

  import_eth_key_to_tpm(key_input)