// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {MagiDeposit} from "../src/MagiDeposit.sol";

interface Vm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function deal(address who, uint256 amount) external;
    function prank(address sender) external;
    function expectRevert(bytes4 sel) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
    function etch(address target, bytes calldata code) external;
}

/// A USDC-like token: transferFrom returns true, or reverts.
contract MockToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function mint(address to, uint256 v) external {
        balanceOf[to] += v;
    }

    function approve(address s, uint256 v) external returns (bool) {
        allowance[msg.sender][s] = v;
        return true;
    }

    function transferFrom(address f, address t, uint256 v) external returns (bool) {
        require(allowance[f][msg.sender] >= v && balanceOf[f] >= v, "insufficient");
        allowance[f][msg.sender] -= v;
        balanceOf[f] -= v;
        balanceOf[t] += v;
        emit Transfer(f, t, v);
        return true;
    }
}

/// transferFrom returns false without moving anything.
contract FalseToken {
    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false;
    }
}

/// transferFrom returns nothing (USDT-style) and moves the tokens.
contract NoReturnToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 v) external {
        balanceOf[to] += v;
    }

    function transferFrom(address f, address t, uint256 v) external {
        require(balanceOf[f] >= v, "insufficient");
        balanceOf[f] -= v;
        balanceOf[t] += v;
    }
}

contract MagiDepositTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant VAULT = address(0x88CBBA6B5e5d2c20d9cFC55f3b2fc18d073cCF14);
    address constant USER = address(0xA11CE);
    bytes32 constant DEPOSIT_SIG = keccak256("Deposit(address,address,uint256,string)");
    MagiDeposit d;

    function setUp() public {
        d = new MagiDeposit(VAULT);
    }

    function _eq(uint256 a, uint256 b, string memory m) internal pure {
        require(a == b, m);
    }

    function testDepositETHGoesToTheVaultAndLogsTheRecipient() public {
        vm.deal(USER, 1 ether);
        vm.recordLogs();
        vm.prank(USER);
        d.deposit{value: 0.4 ether}("hive:alice");
        _eq(VAULT.balance, 0.4 ether, "vault balance");
        _eq(address(d).balance, 0, "contract holds nothing");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        _eq(logs.length, 1, "one log");
        require(logs[0].emitter == address(d), "emitter");
        require(logs[0].topics[0] == DEPOSIT_SIG, "sig");
        require(logs[0].topics[1] == bytes32(uint256(uint160(USER))), "sender topic");
        require(logs[0].topics[2] == bytes32(0), "token topic: ETH");
        (uint256 amount, string memory r) = abi.decode(logs[0].data, (uint256, string));
        _eq(amount, 0.4 ether, "amount");
        require(keccak256(bytes(r)) == keccak256("hive:alice"), "recipient");
    }

    function testDepositTokenGoesStraightToTheVault() public {
        MockToken t = new MockToken();
        t.mint(USER, 5e6);
        vm.prank(USER);
        t.approve(address(d), 5e6);
        vm.recordLogs();
        vm.prank(USER);
        d.depositToken(address(t), 3e6, "did:pkh:eip155:1:0x00000000000000000000000000000000000000b0");
        _eq(t.balanceOf(VAULT), 3e6, "vault");
        _eq(t.balanceOf(address(d)), 0, "contract holds nothing");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        _eq(logs.length, 2, "Transfer then Deposit");
        require(logs[0].emitter == address(t) && logs[1].emitter == address(d), "order");
        require(logs[1].topics[2] == bytes32(uint256(uint160(address(t)))), "token topic");
    }

    function testNoReturnTokenIsAccepted() public {
        NoReturnToken t = new NoReturnToken();
        t.mint(USER, 10);
        vm.prank(USER);
        d.depositToken(address(t), 10, "hive:bob");
        _eq(t.balanceOf(VAULT), 10, "vault");
    }

    function testRefusals() public {
        vm.deal(USER, 1 ether);
        vm.prank(USER);
        vm.expectRevert(MagiDeposit.ZeroAmount.selector);
        d.deposit{value: 0}("hive:alice");
        vm.prank(USER);
        vm.expectRevert(MagiDeposit.BadRecipient.selector);
        d.deposit{value: 1}("");
        bytes memory long = new bytes(129);
        vm.prank(USER);
        vm.expectRevert(MagiDeposit.BadRecipient.selector);
        d.deposit{value: 1}(string(long));
        FalseToken f = new FalseToken();
        vm.prank(USER);
        vm.expectRevert(MagiDeposit.TokenTransferFailed.selector);
        d.depositToken(address(f), 1, "hive:alice");
        vm.prank(USER);
        vm.expectRevert(MagiDeposit.TokenTransferFailed.selector);
        d.depositToken(address(0xdead), 1, "hive:alice"); // no code
        MockToken t = new MockToken(); // no allowance
        vm.prank(USER);
        vm.expectRevert(MagiDeposit.TokenTransferFailed.selector);
        d.depositToken(address(t), 1, "hive:alice");
    }

    /// account-mapping derives this contract's address from these exact bytes
    /// (constants.DepositCreationCode); a compiler or source change must
    /// update both, and this hash, together.
    function testCreationCodeIsTheOneTheBridgeDerivesItsAddressFrom() public pure {
        require(
            keccak256(type(MagiDeposit).creationCode) == 0x14392c96a95bc649b2b82d231436c17e70a3fa11ee2000545193d00aa14b713b,
            "creation code changed: update account-mapping's DepositCreationCode"
        );
    }

    function testPlainETHIsRefused() public {
        vm.deal(USER, 1 ether);
        vm.prank(USER);
        (bool ok,) = address(d).call{value: 1}("");
        require(!ok, "a plain transfer to the deposit contract must revert");
    }

    function testAVaultThatRefusesETHRevertsTheDeposit() public {
        MagiDeposit bad = new MagiDeposit(address(new FalseToken())); // no receive
        vm.deal(USER, 1 ether);
        vm.prank(USER);
        vm.expectRevert(MagiDeposit.ForwardFailed.selector);
        bad.deposit{value: 1}("hive:alice");
    }
}
