// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

interface IZKSBT {
    function getRoot(uint256 tokenId) external view returns (bytes memory);

    function getEncryptedData(
        uint256 tokenId
    ) external view returns (bytes[] memory);

    function mint(
        address to,
        bytes memory root,
        bytes[] memory encryptedData
    ) external payable returns (uint256);

    function verifyProof(
        uint256 tokenId,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[] memory publicValues
    ) external view returns (bool);
}
