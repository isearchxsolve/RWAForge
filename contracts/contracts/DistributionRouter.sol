// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title DistributionRouter
/// @notice Permissionless, bounded ERC-20 batch distribution with protocol fees.
contract DistributionRouter is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant MIN_FEE_BPS = 100;
    uint256 public constant MAX_FEE_BPS = 500;

    /// @dev Conservative upper bound. Larger distributions are submitted as chunks.
    uint256 public constant MAX_RECIPIENTS_PER_CHUNK = 50;

    address public treasury;
    uint256 public feeBps;

    error ZeroAddress();
    error EmptyBatch();
    error ArrayLengthMismatch();
    error ChunkTooLarge(uint256 supplied, uint256 maximum);
    error ZeroRecipient(uint256 index);
    error ZeroAmount(uint256 index);
    error FeeOutOfBounds(uint256 supplied);
    error InvalidTreasury();

    event Distributed(
        address indexed sender,
        address indexed token,
        uint256 recipientCount,
        uint256 totalAmount,
        uint256 feeAmount
    );
    event FeeBpsUpdated(uint256 previousFeeBps, uint256 newFeeBps);
    event TreasuryUpdated(address indexed previousTreasury, address indexed newTreasury);

    constructor(address initialOwner, address initialTreasury, uint256 initialFeeBps)
        Ownable(initialOwner)
    {
        if (initialTreasury == address(0)) revert ZeroAddress();
        if (initialFeeBps < MIN_FEE_BPS || initialFeeBps > MAX_FEE_BPS) {
            revert FeeOutOfBounds(initialFeeBps);
        }

        treasury = initialTreasury;
        feeBps = initialFeeBps;
    }

    /// @notice Distributes one bounded, atomic chunk.
    /// @dev A larger distribution is split by the caller into multiple chunks.
    function distributeChunk(
        address token,
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external nonReentrant {
        uint256 length = recipients.length;

        if (token == address(0)) revert ZeroAddress();
        if (length == 0) revert EmptyBatch();
        if (length != amounts.length) revert ArrayLengthMismatch();
        if (length > MAX_RECIPIENTS_PER_CHUNK) {
            revert ChunkTooLarge(length, MAX_RECIPIENTS_PER_CHUNK);
        }

        uint256 totalAmount;
        for (uint256 i; i < length; ++i) {
            if (recipients[i] == address(0)) revert ZeroRecipient(i);
            if (amounts[i] == 0) revert ZeroAmount(i);
            totalAmount += amounts[i];
        }

        uint256 feeAmount = (totalAmount * feeBps) / BPS_DENOMINATOR;
        IERC20 asset = IERC20(token);

        // Pull once before outbound transfers: all-or-nothing within this chunk.
        asset.safeTransferFrom(msg.sender, address(this), totalAmount + feeAmount);

        for (uint256 i; i < length; ++i) {
            asset.safeTransfer(recipients[i], amounts[i]);
        }

        if (feeAmount != 0) {
            asset.safeTransfer(treasury, feeAmount);
        }

        emit Distributed(msg.sender, token, length, totalAmount, feeAmount);
    }

    function setFeeBps(uint256 newFeeBps) external onlyOwner {
        if (newFeeBps < MIN_FEE_BPS || newFeeBps > MAX_FEE_BPS) {
            revert FeeOutOfBounds(newFeeBps);
        }

        uint256 previousFeeBps = feeBps;
        feeBps = newFeeBps;
        emit FeeBpsUpdated(previousFeeBps, newFeeBps);
    }

    function setTreasury(address newTreasury) external onlyOwner {
        if (newTreasury == address(0)) revert InvalidTreasury();

        address previousTreasury = treasury;
        treasury = newTreasury;
        emit TreasuryUpdated(previousTreasury, newTreasury);
    }
}
