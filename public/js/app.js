// ================= CONFIGURAZIONE SMART CONTRACT =================
const CONTRACT_ADDRESS = "0x95847671fd4c9acca5c83f0b4ca570fd1de9f056";
const ARBITRUM_SEPOLIA_CHAIN_ID = "0x66eee"; // 421614

const CONTRACT_ABI = [
  "function owner() view returns (address)",
  "function getHostCount() view returns (uint256)",
  "function activeHostCount() view returns (uint256)",
  "function totalBatchesAnchored() view returns (uint256)",
  "function getAllHosts() view returns (address[])",
  "function registeredHosts(address) view returns (string hostname, string ipAddress, bool isActive, uint256 registeredAt)",
  "function registerHost(address _hostAddress, string _hostname, string _ipAddress) external",
  "function offboardHost(address _hostAddress) external",
  "function reactivateHost(address _hostAddress) external",
  "function batchRoots(string) view returns (bytes32)",
  "event BatchAnchored(string indexed batchId, bytes32 indexed merkleRoot, address indexed recorder, uint256 timestamp, uint256 logCount)"
];

let provider = null;
let signer = null;
let contract = null;
let currentAddress = null;
let isCurrentAdmin = false;

// ================= UTILITY UI =================
function copyToClipboard(text, btn) {
  if (!navigator.clipboard) {
    const temp = document.createElement("textarea");
    temp.value = text;
    document.body.appendChild(temp);
    temp.select();
    document.execCommand("copy");
    document.body.removeChild(temp);
  } else {
    navigator.clipboard.writeText(text);
  }

  if (btn) {
    const originalHtml = btn.innerHTML;
    btn.innerHTML = "✓";
    btn.classList.add("text-emerald-400");
    setTimeout(() => {
      btn.innerHTML = originalHtml;
      btn.classList.remove("text-emerald-400");
    }, 1500);
  }
}

// ================= CONNESSIONE E GUARDIA SESSIONE =================
async function initWeb3Connection() {
  if (!window.ethereum) {
    throw new Error("MetaMask non rilevato nel browser.");
  }
  provider = new ethers.BrowserProvider(window.ethereum);
  signer = await provider.getSigner();
  currentAddress = await signer.getAddress();
  contract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);

  try {
    const ownerAddr = await contract.owner();
    isCurrentAdmin = (currentAddress.toLowerCase() === ownerAddr.toLowerCase());
  } catch (e) {
    console.warn("Impossibile verificare owner:", e);
    isCurrentAdmin = false;
  }
}

async function requireAuth(activePage, options = {}) {
  const savedAuth = sessionStorage.getItem("sentinel_auth");
  if (!savedAuth || !window.ethereum) {
    window.location.href = "/index.html";
    return false;
  }

  try {
    const accounts = await window.ethereum.request({ method: "eth_accounts" });
    if (!accounts || accounts.length === 0 || accounts[0].toLowerCase() !== savedAuth.toLowerCase()) {
      sessionStorage.removeItem("sentinel_auth");
      window.location.href = "/index.html";
      return false;
    }

    await initWeb3Connection();

    if (options.adminOnly && !isCurrentAdmin) {
      alert("Accesso negato: questa sezione è riservata all'Owner del contratto.");
      window.location.href = "/dashboard.html";
      return false;
    }

    renderNavbar(activePage);
    return true;
  } catch (err) {
    console.error("Errore ripristino sessione:", err);
    sessionStorage.removeItem("sentinel_auth");
    window.location.href = "/index.html";
    return false;
  }
}

function logout() {
  sessionStorage.removeItem("sentinel_auth");
  sessionStorage.removeItem("sentinel_aes_key");
  window.location.href = "/index.html";
}

function renderNavbar(activePage) {
  const navContainer = document.getElementById("appNavbar");
  if (!navContainer) return;

  const shortAddr = currentAddress ? `${currentAddress.slice(0, 6)}...${currentAddress.slice(-4)}` : "";
  const roleBadge = isCurrentAdmin
    ? `<span class="px-2 py-0.5 rounded bg-amber-950 border border-amber-600/60 text-amber-300 text-[10px] font-bold uppercase">Owner SOC</span>`
    : `<span class="px-2 py-0.5 rounded bg-sky-950 border border-sky-700/60 text-sky-300 text-[10px] font-bold uppercase">Auditor</span>`;

  const navLink = (href, id, icon, label) => {
    const isActive = activePage === id;
    const cls = isActive
      ? "bg-sky-600/20 text-sky-300 border border-sky-500/40 font-bold"
      : "text-slate-400 hover:text-slate-200 hover:bg-slate-700/50 border border-transparent";
    return `<a href="${href}" class="px-3 py-2 rounded-lg text-xs transition flex items-center gap-1.5 ${cls}"><span>${icon}</span>${label}</a>`;
  };

  navContainer.innerHTML = `
    <header class="bg-slate-800 border border-slate-700 rounded-xl p-4 shadow-lg space-y-4">
      <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
        <div class="flex items-center gap-2.5">
          <span class="inline-block w-3 h-3 rounded-full bg-emerald-400 animate-pulse"></span>
          <div>
            <h1 class="text-lg font-bold text-sky-400 tracking-wide">Layer 2 Merkle Sentinel</h1>
            <p class="text-[11px] text-slate-400">Arbitrum Sepolia &bull; Forensic Audit Trail &amp; Batch Hash Chain</p>
          </div>
        </div>

        <div class="flex items-center gap-3 self-end sm:self-center">
          <div class="text-right">
            <div class="flex items-center justify-end gap-1.5">
              ${roleBadge}
              <span class="text-xs font-mono text-sky-300 font-bold">${shortAddr}</span>
            </div>
          </div>
          <button onclick="logout()" class="bg-slate-700 hover:bg-rose-900/70 hover:text-rose-200 text-slate-300 px-3 py-1.5 rounded-lg text-xs font-semibold transition">
            Disconnetti
          </button>
        </div>
      </div>

      <nav class="flex flex-wrap items-center gap-2 pt-3 border-t border-slate-700/80">
        ${navLink("/dashboard.html", "dashboard", "📊", "Dashboard & Nodi")}
        ${navLink("/verifier.html", "verifier", "🌳", "Verifica Forense & Decifratura")}
        ${isCurrentAdmin ? navLink("/admin.html", "admin", "🛡️", "Provisioning Host (Admin)") : ""}
      </nav>
    </header>
  `;
}

// ================= MOTORE CRITTOGRAFICO MERKLE & AES-GCM =================
const MerkleEngine = {
  combineHashes: (a, b) => {
    const aClean = a.toLowerCase();
    const bClean = b.toLowerCase();
    return (aClean <= bClean)
      ? ethers.keccak256(ethers.concat([aClean, bClean]))
      : ethers.keccak256(ethers.concat([bClean, aClean]));
  },
  hashLeaf: (rawLog) => ethers.keccak256(ethers.toUtf8Bytes(rawLog)),
  computeRoot: (leaf, proofArray) => {
    let currentHash = leaf;
    for (let p of proofArray) {
      currentHash = MerkleEngine.combineHashes(currentHash, p);
    }
    return currentHash;
  },
  computeBatchChainHash: (merkleRootHex, prevBatchHashHex, batchId, seqNum) => {
    const payload = `${String(merkleRootHex).toLowerCase()}|${String(prevBatchHashHex).toLowerCase()}|${batchId}|${seqNum}`;
    return ethers.keccak256(ethers.toUtf8Bytes(payload));
  }
};

function hexToBytes(hex) {
  const cleanHex = String(hex || "").replace(/^0x/i, "").trim();
  if (cleanHex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(cleanHex)) {
    throw new Error("Formato esadecimale non valido.");
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

async function decryptLogRecord(encryptedObj, hexKey) {
  const cleanKey = String(hexKey || "").replace(/^0x/i, "").trim();
  if (cleanKey.length !== 64) {
    throw new Error("Chiave AES mancante o lunghezza errata (richiesti 64 caratteri hex).");
  }

  const keyBytes = hexToBytes(cleanKey);
  const nonceBytes = hexToBytes(encryptedObj.nonce);
  const ciphertextBytes = hexToBytes(encryptedObj.ciphertext);
  const tagBytes = hexToBytes(encryptedObj.tag);

  const combinedData = new Uint8Array(ciphertextBytes.length + tagBytes.length);
  combinedData.set(ciphertextBytes);
  combinedData.set(tagBytes, ciphertextBytes.length);

  const cryptoKey = await window.crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonceBytes, tagLength: 128 },
    cryptoKey,
    combinedData
  );

  return new TextDecoder().decode(decryptedBuffer);
}

if (window.ethereum) {
  window.ethereum.on("accountsChanged", () => {
    sessionStorage.removeItem("sentinel_auth");
    window.location.href = "/index.html";
  });
}