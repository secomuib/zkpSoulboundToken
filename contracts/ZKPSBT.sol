// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@openzeppelin/contracts/utils/Counters.sol";

import "./SBT/SBT.sol";

/// @title ZKP SBT
/// @author Miquel A. Cabot
/// @notice Soulbound token implementing ZKP
/// @dev Inherits from the SSBT contract
contract ZKPSBT is SBT {
    /* ========== STATE VARIABLES =========================================== */

    using Counters for Counters.Counter;

    Counters.Counter private _tokenIdCounter;

    struct EncryptedData {
        bytes iv; // IV
        bytes ephemPublicKey; // ephemPublicKey
        bytes cipherText; // ciphertext
        bytes mac; // mac
    }

    // Struct to store the encrypted data with the public key of the owner of the SBT
    struct SBTData {
        bytes hashData; // hash of ownerAddress+creditScore without encryption, used to verify the data
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
    ) SBT(name, symbol) {
        Ownable.transferOwnership(admin);
    }

    /* ========== RESTRICTED FUNCTIONS ====================================== */

    function _mintWithCounter(
        address to
    ) internal virtual onlyOwner returns (uint256) {
        uint256 tokenId = _tokenIdCounter.current();
        _tokenIdCounter.increment();
        _mint(to, tokenId);

        return tokenId;
    }

    /* ========== MUTATIVE FUNCTIONS ======================================== */

    /// @notice Mints a new SBT
    /// @dev The caller must have the MINTER role
    /// @param to The address to mint the SBT to
    /// @param hashData Hash of ownerAddress+creditScore without encryption, used to verify the data
    /// @param encryptedCreditScore Encrypted credit score
    /// @param encryptedIncome Encrypted income
    /// @param encryptedReportDate Encrypted report date
    /// @return The SBT ID of the newly minted SBT
    function mint(
        address to,
        bytes calldata hashData,
        EncryptedData calldata encryptedCreditScore,
        EncryptedData calldata encryptedIncome,
        EncryptedData calldata encryptedReportDate
    ) external payable virtual returns (uint256) {
        uint256 tokenId = _mintWithCounter(to);

        sbtData[tokenId] = SBTData({
            hashData: hashData,
            encryptedCreditScore: encryptedCreditScore,
            encryptedIncome: encryptedIncome,
            encryptedReportDate: encryptedReportDate
        });

        emit MintedToAddress(tokenId, to);

        return tokenId;
    }

    /* ========== VIEWS ===================================================== */

    function getHashData(uint256 tokenId) external view returns (bytes memory) {
        return sbtData[tokenId].hashData;
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

    event MintedToAddress(uint256 tokenId, address to);
}
