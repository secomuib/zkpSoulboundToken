// SPDX-License-Identifier: MIT
pragma solidity ^0.8.8;

import "@openzeppelin/contracts/access/Ownable.sol";

import "./eip-4671/ERC4671.sol";

interface IVerifier {
    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[5] memory input
    ) external view returns (bool);
}

/// @title ZKP SBT
/// @author Miquel A. Cabot
/// @notice Soulbound token implementing ZKP
/// @dev Inherits from the SSBT contract
contract ZKSBT is ERC4671, Ownable {
    /* ========== STATE VARIABLES =========================================== */

    IVerifier internal _verifier;

    // Struct to store the encrypted data with the public key of the owner of the SBT
    struct SBTData {
        bytes root; // root of the Merkle Tree's data without encryption, used to verify the data
        // encrypted data with the public key of the owner of the SBT
        bytes encryptedCreditScore;
        bytes encryptedIncome;
        bytes encryptedReportDate;
    }

    // tokenId => SBTData
    mapping(uint256 => SBTData) public sbtData;

    /* ========== INITIALIZE ================================================ */

    /// @notice Creates a new ZKP SBT
    /// @dev Creates a new ZKP SBT, inheriting from the SBT contract.
    /// @param admin Administrator of the smart contract
    /// @param name Name of the token
    /// @param symbol Symbol of the token
    /// @param verifier Verifier smart contract
    constructor(
        address admin,
        string memory name,
        string memory symbol,
        IVerifier verifier
    ) ERC4671(name, symbol) {
        Ownable.transferOwnership(admin);
        _verifier = verifier;
    }

    /* ========== RESTRICTED FUNCTIONS ====================================== */

    /* ========== MUTATIVE FUNCTIONS ======================================== */

    /// @notice Mints a new SBT
    /// @dev The caller must have the MINTER role
    /// @param to The address to mint the SBT to
    /// @param root Root of the Merkle Tree's data without encryption, used to verify the data
    /// @param encryptedCreditScore Encrypted credit score
    /// @param encryptedIncome Encrypted income
    /// @param encryptedReportDate Encrypted report date
    /// @return The SBT ID of the newly minted SBT
    function mint(
        address to,
        bytes calldata root,
        bytes calldata encryptedCreditScore,
        bytes calldata encryptedIncome,
        bytes calldata encryptedReportDate /* onlyOwner */
    ) external payable virtual returns (uint256) {
        uint256 tokenId = _mint(to);

        sbtData[tokenId] = SBTData({
            root: root,
            encryptedCreditScore: encryptedCreditScore,
            encryptedIncome: encryptedIncome,
            encryptedReportDate: encryptedReportDate
        });

        return tokenId;
    }

    /* ========== VIEWS ===================================================== */

    /// @notice Returns the verifier smart contract
    /// @return The verifier smart contract
    function getVerifier() external view returns (IVerifier) {
        return _verifier;
    }

    /// @notice Returns the root of the Merkle Tree's data without encryption, used to verify the data
    /// @param tokenId The SBT ID
    /// @return The root of the Merkle Tree's data without encryption, used to verify the data
    function getRoot(uint256 tokenId) public view returns (bytes memory) {
        return sbtData[tokenId].root;
    }

    /// @notice Returns the encrypted data with the public key of the owner of the SBT
    /// @param tokenId The SBT ID
    /// @return The encrypted data with the public key of the owner of the SBT
    function getEncryptedData(
        uint256 tokenId
    ) external view returns (bytes memory, bytes memory, bytes memory) {
        return (
            sbtData[tokenId].encryptedCreditScore,
            sbtData[tokenId].encryptedIncome,
            sbtData[tokenId].encryptedReportDate
        );
    }

    // @notice verifies the validity of the proof, and make further verifications on the public
    // input of the circuit
    // @param a First part of the proof
    // @param b Second part of the proof
    // @param c Third part of the proof
    // @param publicValues Public input of the circuit
    // @param tokenId The SBT ID
    // @return True if the proof is valid, false otherwise
    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[] memory publicValues,
        uint256 tokenId
    ) external view returns (bool) {
        // convert dynamic array to fixed array
        uint[5] memory pValues;
        for (uint i = 0; i < pValues.length; i++) {
            pValues[i] = publicValues[i];
        }

        address owner = address(uint160(publicValues[2]));

        require(
            publicValues[0] ==
                0x0000000000000000000000000000000000000000000000000000000000000001,
            "The claim doesn't satisfy the query condition"
        );

        require(
            ownerOf(tokenId) == owner,
            "The SBT doesn't belong to the address that is trying to claim the loan"
        );

        bytes memory root = getRoot(tokenId);
        require(
            keccak256(abi.encodePacked(root)) ==
                keccak256(abi.encodePacked(publicValues[1])),
            "The root of the Merkle Tree's data doesn't match the root stored in the SBT"
        );

        require(
            _verifier.verifyProof(a, b, c, pValues),
            "Proof verification failed"
        );

        return true;
    }

    /* ========== PRIVATE FUNCTIONS ========================================= */

    /* ========== MODIFIERS ================================================= */

    /* ========== EVENTS ==================================================== */
}
