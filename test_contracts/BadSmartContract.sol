pragma solidity ^0.4.0;

contract BadSmartContract {
    uint256 private lockTime;
    bool private locked = false;
    uint256 balance;
    
    // Vulnerability: Reentrancy
    function withdraw(uint amount) public {
        require(msg.sender.call.value(amount)());
        balance -= amount;
    }
    
    // Vulnerability: Integer Overflow
    function add(uint256 a, uint256 b) public returns (uint256) {
        return a + b;
    }
    
    // Vulnerability: Timestamp dependency
    function isReady() public returns (bool) {
        return now >= lockTime;
    }
    
    // Vulnerability: Unprotected function
    function destroy() public {
        selfdestruct(msg.sender);
    }
}
