# First Flight #1: PasswordStore - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. test_owner_can_set_password() doesn't check non-owner](#H-01)
    - ### [H-02. setPassword doesn't check ownership allows anyone to set password](#H-02)

- ## Low Risk Findings
    - ### [L-01. Error name doesn't follow Solidity naming convention](#L-01)
    - ### [L-02. event name for setting new password has a type ](#L-02)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #1

### Dates: Oct 18th, 2023 - Oct 25th, 2023

[See more contest details here](https://www.codehawks.com/contests/clnuo221v0001l50aomgo4nyn)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 2
   - Medium: 0
   - Low: 2


# High Risk Findings

## <a id='H-01'></a>H-01. test_owner_can_set_password() doesn't check non-owner            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-PasswordStore/blob/856ed94bfcf1031bf9d13514cb21b591d88ed323/test/PasswordStore.t.sol#L19

## Summary
This test only checks the case when owner sets the password. 
## Vulnerability Details
Test doesn't check any other address except the owner's one. It is equally important to check a non-owner scenario. 
## Impact
This incomplete test results in the function ```setPassword()``` to keep working and not generating an error.
## Tools Used
Manual check.
## Recommendations
Add a check with non-owner address, e.g. ```vm.startPrank(address(1))```. 
## <a id='H-02'></a>H-02. setPassword doesn't check ownership allows anyone to set password            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-PasswordStore/blob/856ed94bfcf1031bf9d13514cb21b591d88ed323/src/PasswordStore.sol#L26

## Summary
Anyone can set a new password via ```setPassword()```.
## Vulnerability Details
No ownership check is made in ```setPassword()```.
## Impact
High. The issue is easy to find and the attacker can obtain access to the contract.
## Tools Used
Manual check.
## Recommendations
Check if ```msg.sender == owner``` directly in ```setPassword()``` or create an ```onlyOwner()``` modifier _and apply_ the modifier to ```setPassword()```. Revert if ```msg.sender``` is not the owner.


		


# Low Risk Findings

## <a id='L-01'></a>L-01. Error name doesn't follow Solidity naming convention            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-PasswordStore/blob/856ed94bfcf1031bf9d13514cb21b591d88ed323/src/PasswordStore.sol#L11

## Summary
The following error:
```
error PasswordStore__NotOwner();
```
don't follow Solidity [naming conventions](https://docs.soliditylang.org/en/latest/style-guide.html#naming-conventions).
## Vulnerability Details

## Impact
Low impact. Doesn't affect the smart contract safety.
## Tools Used
Manual check.
## Recommendations
Change the error name according to Solidity naming convention, e.g.:
```
error PasswordStoreNotOwner();
```
## <a id='L-02'></a>L-02. event name for setting new password has a type             

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-10-PasswordStore/blob/856ed94bfcf1031bf9d13514cb21b591d88ed323/src/PasswordStore.sol#L16

## Summary
event ```SetNetPassword``` has incorrect name.
## Vulnerability Details
Typo in event name.
## Impact
For a larger smart contract especially in case when some kind of Net-related code this current event name can lead to confusion.
## Tools Used
Manual check.
## Recommendations
Change event name to ```SetNewPassword```.


