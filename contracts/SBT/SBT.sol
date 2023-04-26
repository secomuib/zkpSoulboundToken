// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.7;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "./ISBT.sol";
import "./ISBTMetadata.sol";

/// @title SBT
/// @notice Soulbound token is an NFT token that is not transferable.
contract SBT is Context, ERC165, ISBT, ISBTMetadata, Ownable {
    using Strings for uint256;

    // Token name
    string internal _name;

    // Token symbol
    string internal _symbol;

    // Mapping from token ID to owner address
    mapping(uint256 => address) internal _owners;

    // Mapping owner address to token count
    mapping(address => uint256) internal _balances;

    /**
     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.
     */
    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(ISBT).interfaceId ||
            interfaceId == type(ISBTMetadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /**
     * @dev See {ISBT-balanceOf}.
     */
    function balanceOf(
        address owner
    ) public view virtual override returns (uint256) {
        require(owner != address(0), "SBT: address zero is not a valid owner");
        return _balances[owner];
    }

    /**
     * @dev See {ISBTMetadata-name}.
     */
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /**
     * @dev See {ISBTMetadata-symbol}.
     */
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev See {ISBTMetadata-tokenURI}.
     */
    function tokenURI(
        uint256 tokenId
    ) public view virtual override returns (string memory) {
        _requireMinted(tokenId);

        string memory baseURI = _baseURI();
        return
            bytes(baseURI).length > 0
                ? string(abi.encodePacked(baseURI, tokenId.toString()))
                : "";
    }

    /**
     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each
     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty
     * by default, can be overridden in child contracts.
     */
    function _baseURI() internal view virtual returns (string memory) {
        return "";
    }

    /**
     * @dev Returns whether `tokenId` exists.
     *
     * Tokens can be managed by their owner.
     *
     * Tokens start existing when they are minted (`_mint`),
     * and stop existing when they are burned (`_burn`).
     */
    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return _owners[tokenId] != address(0);
    }

    /**
     * @dev Destroys `tokenId`.
     *
     * Requirements:
     * - `tokenId` must exist.
     *
     * Emits a {Burn} event.
     */
    function _burn(uint256 tokenId) internal virtual {
        address owner = ownerOf(tokenId);

        _balances[owner] -= 1;
        delete _owners[tokenId];

        emit Burn(owner, tokenId);
    }

    /**
     * @dev Reverts if the `tokenId` has not been minted yet.
     */
    function _requireMinted(uint256 tokenId) internal view virtual {
        require(_exists(tokenId), "SBT: invalid token ID");
    }

    function ownerOf(
        uint256 tokenId
    ) public view virtual override returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "SBT: owner query for nonexistent token");
        return owner;
    }

    /**
     * @dev Mints `tokenId` and transfers it to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible
     *
     * Requirements:
     *
     * - `tokenId` must not exist.
     * - `to` cannot be the zero address.
     *
     * Emits a {TransferRequest} event.
     */
    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "SBT: mint to the zero address");
        require(!_exists(tokenId), "SBT: token already minted");

        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Mint(to, tokenId);
    }
}
