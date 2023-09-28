// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@openzeppelin/contracts/access/Ownable.sol";

import "./eip-4671/ERC4671.sol";

/// @title ZKP SBT
/// @author Miquel A. Cabot
/// @notice Soulbound token implementing ZKP
/// @dev Inherits from the SSBT contract
contract ZKPSBT is ERC4671, Ownable {
    /* ========== STATE VARIABLES =========================================== */

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
    constructor(
        address admin,
        string memory name,
        string memory symbol
    ) ERC4671(name, symbol) {
        Ownable.transferOwnership(admin);
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

    function getRoot(uint256 tokenId) external view returns (bytes memory) {
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

    /* ========== PRIVATE FUNCTIONS ========================================= */

    /* ========== MODIFIERS ================================================= */

    /* ========== EVENTS ==================================================== */
}
