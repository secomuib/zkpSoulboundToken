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

    IVerifier verifier;

    struct EncryptedData {
        bytes iv; // IV
        bytes ephemPublicKey; // ephemPublicKey
        bytes ciphertext; // ciphertext
        bytes mac; // mac
    }

    // Struct to store the encrypted data with the public key of the owner of the SBT
    struct SBTData {
        bytes root; // root of the Merkle Tree's data without encryption, used to verify the data
        // encrypted data with the public key of the owner of the SBT
        EncryptedData encryptedCreditScore;
        EncryptedData encryptedIncome;
        EncryptedData encryptedReportDate;
    }

    // tokenId => SBTData
    mapping(uint256 => SBTData) public sbtData;

    /* ========== INITIALIZE ================================================ */

    /// @notice Creates a new ZKP SBT
    /// @dev Creates a new ZKP SBT, inheriting from the SBT contract.
    /// @param admin Administrator of the smart contract
    /// @param name Name of the token
    /// @param symbol Symbol of the token
    /// @param _verifier Verifier smart contract
    constructor(
        address admin,
        string memory name,
        string memory symbol,
        IVerifier _verifier
    ) ERC4671(name, symbol) {
        Ownable.transferOwnership(admin);
        verifier = _verifier;
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
        EncryptedData calldata encryptedCreditScore,
        EncryptedData calldata encryptedIncome,
        EncryptedData calldata encryptedReportDate /* onlyOwner */
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

    function getRoot(uint256 tokenId) public view returns (bytes memory) {
        return sbtData[tokenId].root;
    }

    function getEncryptedData(
        uint256 tokenId
    )
        external
        view
        returns (
            EncryptedData memory,
            EncryptedData memory,
            EncryptedData memory
        )
    {
        return (
            sbtData[tokenId].encryptedCreditScore,
            sbtData[tokenId].encryptedIncome,
            sbtData[tokenId].encryptedReportDate
        );
    }

    // @notice verifies the validity of the proof, and make further verifications on the public
    // input of the circuit
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
            verifier.verifyProof(a, b, c, pValues),
            "Proof verification failed"
        );

        return true;
    }

    /* ========== PRIVATE FUNCTIONS ========================================= */

    /* ========== MODIFIERS ================================================= */

    /* ========== EVENTS ==================================================== */
}
