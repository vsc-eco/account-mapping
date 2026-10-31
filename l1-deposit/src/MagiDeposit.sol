// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @title MagiDeposit
/// @notice Deposits into the Magi EVM bridge for an explicit Magi recipient
/// (RP-7). A plain transfer to the vault is credited to its sender, which is
/// wrong for a deposit from a smart wallet, a custodian or any contract; this
/// contract carries the recipient instead.
///
/// It holds nothing: each call moves the funds to the vault in the same call
/// and logs Deposit. It has no owner, no admin and no upgrade path. It is
/// deployed with CREATE2 through the deterministic deployment proxy
/// (0x4e59b44847b379578588920cA78FbF26c0B4956C, salt 0) with the vault as its
/// constructor argument, so its address is a function of the vault: the bridge
/// accepts Deposit logs only from the address it derives for its own vault.
contract MagiDeposit {
    /// @notice The bridge vault (the TSS key's address) every deposit goes to.
    address public immutable vault;

    /// @notice A deposit of `amount` of `token` (address(0) for ETH) from
    /// `sender`, for the Magi account `recipient` (e.g. "hive:alice").
    event Deposit(address indexed sender, address indexed token, uint256 amount, string recipient);

    error ZeroVault();
    error ZeroAmount();
    error BadRecipient();
    error ForwardFailed();
    error TokenTransferFailed();

    constructor(address vault_) {
        if (vault_ == address(0)) revert ZeroVault();
        vault = vault_;
    }

    /// @notice Deposit ETH for `recipient`.
    function deposit(string calldata recipient) external payable {
        if (msg.value == 0) revert ZeroAmount();
        _checkRecipient(recipient);
        (bool ok,) = vault.call{value: msg.value}("");
        if (!ok) revert ForwardFailed();
        emit Deposit(msg.sender, address(0), msg.value, recipient);
    }

    /// @notice Deposit `amount` of `token` for `recipient`; this contract must
    /// be approved for `amount`. The tokens go straight from the sender to the
    /// vault (transferFrom).
    function depositToken(address token, uint256 amount, string calldata recipient) external {
        if (amount == 0) revert ZeroAmount();
        _checkRecipient(recipient);
        if (token.code.length == 0) revert TokenTransferFailed();
        (bool ok, bytes memory ret) = token.call(abi.encodeWithSelector(0x23b872dd, msg.sender, vault, amount));
        if (!ok || (ret.length != 0 && (ret.length != 32 || abi.decode(ret, (uint256)) != 1))) {
            revert TokenTransferFailed();
        }
        emit Deposit(msg.sender, token, amount, recipient);
    }

    /// @dev The bridge checks the recipient is a Magi account; this only
    /// bounds it (a Magi account name is short).
    function _checkRecipient(string calldata recipient) private pure {
        uint256 n = bytes(recipient).length;
        if (n == 0 || n > 128) revert BadRecipient();
    }
}
