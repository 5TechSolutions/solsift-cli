pragma solidity ^0.4.25;

contract VulnerableToken {
    mapping(address => uint256) public balances;
    address public owner;
    
    function VulnerableToken() public {
        owner = msg.sender;
        balances[owner] = 1000000;
    }
    
    // Vulnerability 1: Unchecked Call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        require(msg.sender.call.value(amount)(""));
        balances[msg.sender] -= amount;
    }
    
    // Vulnerability 2: Reentrancy
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
    
    // Vulnerability 3: Integer Overflow
    function mint(uint256 amount) public {
        require(msg.sender == owner);
        balances[msg.sender] = balances[msg.sender] + amount;
    }
}
