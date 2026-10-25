// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title RewardClaimer
/// @notice Merkle claims with recipient-authorized, replay-protected relayed claims.
contract RewardClaimer is Ownable, EIP712, ReentrancyGuard {
    using SafeERC20 for IERC20;

    bytes32 public constant CLAIM_FOR_TYPEHASH =
        keccak256(
            "ClaimFor(uint256 index,address account,uint256 amount,bytes32 merkleRoot,address relayer,uint256 nonce,uint256 deadline)"
        );

    IERC20 public immutable rewardToken;
    bytes32 public merkleRoot;
    uint256 public epoch;

    mapping(uint256 => mapping(uint256 => uint256)) private _claimedBitMap;
    mapping(address => uint256) public nonces;

    error ZeroAddress();
    error InvalidProof();
    error AlreadyClaimed(uint256 epoch, uint256 index);
    error SignatureExpired(uint256 deadline);
    error InvalidRelayer(address expected, address actual);
    error InvalidSignature();
    error ZeroAmount();

    event MerkleRootUpdated(uint256 indexed epoch, bytes32 indexed merkleRoot);
    event Claimed(
        uint256 indexed epoch,
        uint256 indexed index,
        address indexed account,
        uint256 amount,
        address caller
    );

    constructor(address initialOwner, IERC20 rewardToken_, bytes32 initialMerkleRoot)
        Ownable(initialOwner)
        EIP712("RWAForge RewardClaimer", "1")
    {
        if (address(rewardToken_) == address(0)) revert ZeroAddress();

        rewardToken = rewardToken_;
        merkleRoot = initialMerkleRoot;
        emit MerkleRootUpdated(0, initialMerkleRoot);
    }

    function isClaimed(uint256 claimEpoch, uint256 index) public view returns (bool) {
        uint256 wordIndex = index >> 8;
        uint256 bitIndex = index & 255;
        return (_claimedBitMap[claimEpoch][wordIndex] & (1 << bitIndex)) != 0;
    }

    /// @notice Sets a new independent Merkle epoch.
    function setMerkleRoot(bytes32 newMerkleRoot) external onlyOwner {
        merkleRoot = newMerkleRoot;
        unchecked {
            ++epoch;
        }
        emit MerkleRootUpdated(epoch, newMerkleRoot);
    }

    /// @notice Claims a reward directly for the sender.
    function claim(
        uint256 index,
        uint256 amount,
        bytes32[] calldata merkleProof
    ) external nonReentrant {
        _claim(index, msg.sender, amount, merkleProof);
    }

    /// @notice Claims for `account` using that account's EIP-712 authorization.
    function claimFor(
        uint256 index,
        address account,
        uint256 amount,
        bytes32[] calldata merkleProof,
        address relayer,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant {
        if (block.timestamp > deadline) revert SignatureExpired(deadline);
        if (msg.sender != relayer) revert InvalidRelayer(relayer, msg.sender);

        uint256 nonce = nonces[account]++;
        bytes32 structHash = keccak256(
            abi.encode(
                CLAIM_FOR_TYPEHASH,
                index,
                account,
                amount,
                merkleRoot,
                relayer,
                nonce,
                deadline
            )
        );

        address signer = ECDSA.recover(_hashTypedDataV4(structHash), signature);
        if (signer != account) revert InvalidSignature();

        _claim(index, account, amount, merkleProof);
    }

    function _claim(
        uint256 index,
        address account,
        uint256 amount,
        bytes32[] calldata merkleProof
    ) private {
        if (account == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (isClaimed(epoch, index)) revert AlreadyClaimed(epoch, index);

        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(index, account, amount))));
        if (!MerkleProof.verify(merkleProof, merkleRoot, leaf)) revert InvalidProof();

        uint256 wordIndex = index >> 8;
        uint256 bitIndex = index & 255;
        _claimedBitMap[epoch][wordIndex] |= (1 << bitIndex);

        rewardToken.safeTransfer(account, amount);
        emit Claimed(epoch, index, account, amount, msg.sender);
    }
}
