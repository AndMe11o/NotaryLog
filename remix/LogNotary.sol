// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title LogNotary
 * @notice Piattaforma enterprise di log notarization e forensic audit trail su Arbitrum Sepolia L2.
 * @dev Utilizza Merkle Tree per comprimere le transazioni di log e conservare l'integrità probatoria.
 */
contract LogNotary is Ownable {

    // --- STRUCTS ---

    struct Host {
        string hostname;
        string ipAddress;
        bool isActive;
        uint256 registeredAt;
    }

    struct BatchMetadata {
        bytes32 merkleRoot;
        address recorder;
        uint256 timestamp;
        uint256 logCount;
    }

    // --- STATE VARIABLES ---

    // Mapping: indirizzo host => dati del server registrato
    mapping(address => Host) public registeredHosts;
    // Array per l'iterazione e l'indicizzazione di tutti gli host censiti
    address[] public hostList;

    // Mapping: batchId => Merkle Root ancorata
    mapping(string => bytes32) public batchRoots;
    // Mapping: batchId => Metadati del batch (timestamp, recorder, logCount)
    mapping(string => BatchMetadata) public batchMetadata;

    // Contatori globali per metriche SOC
    uint256 public totalBatchesAnchored;
    uint256 public activeHostCount;

    // --- CUSTOM ERRORS (Gas Optimization) ---

    error HostAlreadyRegistered(address hostAddress);
    error HostNotFound(address hostAddress);
    error HostNotActive(address hostAddress);
    error InvalidZeroAddress();
    error EmptyStringParameter();
    error BatchAlreadyExists(string batchId);
    error BatchNotFound(string batchId);
    error InvalidMerkleRoot();
    error InvalidLogCount();

    // --- EVENTS ---

    event HostRegistered(
        address indexed hostAddress, 
        string hostname, 
        string ipAddress, 
        uint256 timestamp
    );
    
    event HostStatusUpdated(
        address indexed hostAddress, 
        bool isActive, 
        uint256 timestamp
    );

    event BatchAnchored(
        string indexed batchId, 
        bytes32 indexed merkleRoot, 
        address indexed recorder, 
        uint256 timestamp, 
        uint256 logCount
    );

    // --- MODIFIERS ---

    modifier onlyActiveHost() {
        if (!registeredHosts[msg.sender].isActive) {
            revert HostNotActive(msg.sender);
        }
        _;
    }

    // --- CONSTRUCTOR ---

    constructor() Ownable(msg.sender) {}

    // --- HOST REGISTRY (Owner / SOC Admin Only) ---

    /**
     * @notice Registra un nuovo server Linux/VPS autorizzato ad ancorare radici di Merkle.
     * @param _hostAddress L'indirizzo del wallet configurato sull'Agent VPS.
     * @param _hostname Nome identificativo della macchina (es. "srv-prod-ssh-01").
     * @param _ipAddress Indirizzo IP del server.
     */
    function registerHost(
        address _hostAddress, 
        string calldata _hostname, 
        string calldata _ipAddress
    ) external onlyOwner {
        if (_hostAddress == address(0)) revert InvalidZeroAddress();
        if (bytes(_hostname).length == 0 || bytes(_ipAddress).length == 0) revert EmptyStringParameter();
        if (registeredHosts[_hostAddress].registeredAt != 0) revert HostAlreadyRegistered(_hostAddress);

        registeredHosts[_hostAddress] = Host({
            hostname: _hostname,
            ipAddress: _ipAddress,
            isActive: true,
            registeredAt: block.timestamp
        });

        hostList.push(_hostAddress);
        activeHostCount++;

        emit HostRegistered(_hostAddress, _hostname, _ipAddress, block.timestamp);
    }

    /**
     * @notice Disattiva un server compromesso o dismesso (offboarding).
     * @param _hostAddress L'indirizzo dell'host da disattivare.
     */
    function offboardHost(address _hostAddress) external onlyOwner {
        if (registeredHosts[_hostAddress].registeredAt == 0) revert HostNotFound(_hostAddress);
        if (!registeredHosts[_hostAddress].isActive) revert HostNotActive(_hostAddress);

        registeredHosts[_hostAddress].isActive = false;
        activeHostCount--;

        emit HostStatusUpdated(_hostAddress, false, block.timestamp);
    }

    /**
     * @notice Riattiva un host precedentemente disattivato.
     * @param _hostAddress L'indirizzo dell'host da riattivare.
     */
    function reactivateHost(address _hostAddress) external onlyOwner {
        if (registeredHosts[_hostAddress].registeredAt == 0) revert HostNotFound(_hostAddress);
        if (registeredHosts[_hostAddress].isActive) revert HostAlreadyRegistered(_hostAddress);

        registeredHosts[_hostAddress].isActive = true;
        activeHostCount++;

        emit HostStatusUpdated(_hostAddress, true, block.timestamp);
    }

    // --- BATCH ANCHORING (Host Only) ---

    /**
     * @notice Ancola la Merkle Root calcolata dall'Agent VPS su L2.
     * @param _batchId UUID identificativo del batch.
     * @param _merkleRoot Radice crittografica dei log contenuti nel batch.
     * @param _logCount Numero di log racchiusi nel batch.
     */
    function recordBatchRoot(
        string calldata _batchId, 
        bytes32 _merkleRoot,
        uint256 _logCount
    ) external onlyActiveHost {
        if (bytes(_batchId).length == 0) revert EmptyStringParameter();
        if (_merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (_logCount == 0) revert InvalidLogCount();
        if (batchRoots[_batchId] != bytes32(0)) revert BatchAlreadyExists(_batchId);

        batchRoots[_batchId] = _merkleRoot;
        batchMetadata[_batchId] = BatchMetadata({
            merkleRoot: _merkleRoot,
            recorder: msg.sender,
            timestamp: block.timestamp,
            logCount: _logCount
        });

        totalBatchesAnchored++;

        emit BatchAnchored(_batchId, _merkleRoot, msg.sender, block.timestamp, _logCount);
    }

    // --- AUDIT & FORENSIC VERIFICATION (View / Gasless) ---

    /**
     * @notice Verifica matematicamente l'inclusione probatoria di un singolo log all'interno di un batch.
     * @param _batchId ID del batch di riferimento.
     * @param _leaf Hash (foglia) del log specifico.
     * @param _proof Percorso di Merkle generato per la foglia.
     * @return isValid True se il log è matematicamente integro e certificato.
     * @return timestamp Timestamp del blocco in cui la root è stata ancorata.
     * @return recorder Indirizzo del server VPS che ha effettuato l'ancoraggio.
     */
    function verifyLeafProof(
        string calldata _batchId, 
        bytes32 _leaf, 
        bytes32[] calldata _proof
    ) external view returns (bool isValid, uint256 timestamp, address recorder) {
        bytes32 root = batchRoots[_batchId];
        if (root == bytes32(0)) revert BatchNotFound(_batchId);

        isValid = MerkleProof.verify(_proof, root, _leaf);
        
        BatchMetadata memory meta = batchMetadata[_batchId];
        return (isValid, meta.timestamp, meta.recorder);
    }

    // --- GETTERS & METRICHE ---

    /**
     * @notice Restituisce il numero totale di server censiti.
     */
    function getHostCount() external view returns (uint256) {
        return hostList.length;
    }

    /**
     * @notice Restituisce la lista completa degli indirizzi degli host per le dashboard di visualizzazione.
     */
    function getAllHosts() external view returns (address[] memory) {
        return hostList;
    }
}