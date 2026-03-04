pragma solidity ^0.4.0;

contract CriticalSmartContract {
    uint256 private lockTime;
    bool locked;
    address owner;
    
    // CRITICAL: Can send all contract balance
    function drain() public {
        selfdestruct(msg.sender);
    }
    
    // CRITICAL: Reentrancy without protection
    function withdraw(uint amount) public {
        if (balances[msg.sender] >= amount) {
            msg.sender.call.value(amount)("");
            balances[msg.sender] -= amount;
        }
    }
    
    mapping(address => uint256) balances;
}
