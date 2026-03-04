// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24; // <-- SWC-102: Outdated compiler version, SWC-103: Floating pragma

interface IERC20 {
    function totalSupply() external view returns (uint);
    function balanceOf(address owner) external view returns (uint);
    function transfer(address to, uint amount) external returns (bool);
    function transferFrom(address from, address to, uint amount) external returns (bool);
    function approve(address spender, uint amount) external returns (bool);
}

contract SimpleDex {
    struct LiquidityProvider {
        uint amount;
        uint lastAdded;
    }

    // SWC-136: Unencrypted secrets on-chain
    string public secretAdminPassword = "admin1234";
    // SWC-131: Unused variable
    // SWC-108: State variable default visibility
    uint unused;
    address public owner;

    address[] public users;

    mapping(address => uint) public shares;
    mapping(address => uint) public reserves;
    mapping(address => LiquidityProvider) public providers;
    mapping(bytes32 => bool) public usedSignatures;

    // SWC-118: Incorrect constructor name (only possible in 0.4.24)
    function SimpleDex() public {
    // constructor () public {
        owner = msg.sender;
    }

    // SWC-132: Unexpected Ether balance
    function () public payable {} // fallback that does nothing (possible only in 0.4.24)

    // SWC-115: Authorization via tx.origin
    function onlyOwner() public {
        require(tx.origin == owner); 
    }

    // SWC-116 & SWC-120: Block values used for randomness
    function getRandomNumber() public view returns (uint) {
        return uint(blockhash(block.number - 1)) % 100 + block.timestamp;
    }

    function addLiquidity(address tokenAddress, uint amount) external {
        // SWC-104: Unchecked return values
        IERC20(tokenAddress).transferFrom(msg.sender, address(this), amount);

        // SWC-109: Uninitialized storage pointer (possible only in old solidity versions)
        LiquidityProvider storage lp;
        lp.amount = amount;
        lp.lastAdded = block.timestamp;

        // SWC-101: Integer overflow/underflow
        shares[msg.sender] =+ amount; // SWC-129: Typography error (only possible in 0.4.24)
        // shares[msg.sender] += amount;
        reserves[tokenAddress] += amount;
    }

    // In solidity 0.4.24 removing 'external' will cause SWC-100 vulnerability
    function removeLiquidity(address tokenAddress, uint share) {
        uint amount = share * reserves[tokenAddress];

        // SWC-107: Reentrancy vulnerability - state changes after external call
        IERC20(tokenAddress).transfer(msg.sender, amount);

        // SWC-101: Integer underflow
        shares[msg.sender] -= share;
        reserves[tokenAddress] -= amount;
    }

    function swap(address tokenIn, uint amountIn, address tokenOut) external {
        // SWC-104: Unchecked return value
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);

        (uint reserveIn, uint reserveOut) = (reserves[tokenIn], reserves[tokenOut]);

        uint amountOut = (amountIn * reserveOut) / (reserveIn + amountIn);

        // SWC-107: Reentrancy vulnerability
        IERC20(tokenOut).transfer(msg.sender, amountOut);

        // SWC-101: Integer overflow/underflow
        reserves[tokenIn] += amountIn;
        reserves[tokenOut] -= amountOut;
    }

    //
    // SWC-117: Signature malleability
    // SWC-122: Missing signature validation logic
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (bool) {
        ecrecover(hash, v, r, s); // No s value validation
        return true;
    }

    //
    // SWC-121: No replay protection
    function submitSigned(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0));
        // No nonce or replay protection!
        usedSignatures[hash] = true;
    }

    // SWC-112: delegatecall
    // In 0.4.24 without calldata is possible
    function delegateTo(address callee, bytes data) external {
        // SWC-111: Deprecated solidity function (should be delegatecall)
        require(callee.callcode(data));
        // (bool a, bytes memory b) = callee.delegatecall(data);
    }

    // SWC-106: Anyone can destroy contract
    function destroy() external {
        // SWC-111: Deprecated solidity function (should be selfdestruct, possible only in 0.4.24)
        suicide(msg.sender);
        // selfdestruct(msg.sender);
    }

    function getReserves(address token) external view returns (uint) {
        return reserves[token];
    }

    function getTokenOut(address tokenIn, uint amountIn, address tokenOut) external view returns (uint) {
        (uint reserveIn, uint reserveOut) = (reserves[tokenIn], reserves[tokenOut]);

        return (amountIn * reserveOut) / (reserveIn + amountIn);
    }

    // SWC-134: Hardcoded gas call
    // In 0.4.24 without calldata is possible
    // Possible only in 0.4.24
    function lowGasCall(address target, bytes data) external {
        require(target.call.gas(10000)(data));
    }

    // SWC-119: Shadowing state variable
    function shadowVariable() public {
        uint shares = 123;
    }

    //
    // SWC-133: Hash collision (abi.encodePacked misuse)
    // In 0.4.24 without memory is possible
    function collisionExample(string a, uint b) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }

    // SWC-135: Code with no effects 
    function getAddressAmount(address user) external view returns (uint) {
        // SWC-110: Assert violation
        assert(false);

        providers[user].amount;
    }

    // SWC-113: DoS with failed call (Mythril)
    // Possible only in 0.4.24
    function triggerFail() public {
        require(address(this).call(bytes4(keccak256("nonExistent()"))));
    }

    function addUser(address user) public {
        users.push(user);
    }

    // SWC-128: Block gas limit - loop
    function loopUsers() public {
        for (uint i = 0; i < users.length; i++) {
            address _user = users[i];
            shares[_user] += 1;
        }
    }
}
