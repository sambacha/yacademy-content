# YAcademy Quick Examples

- [YAcademy Quick Examples](#yacademy-quick-examples)
- [Incorrect interface](#incorrect-interface)
  - [Alice.sol](#alicesol)
  - [Bob.sol](#bobsol)
- [Incorrect interface](#incorrect-interface-1)
  - [Attack Scenario](#attack-scenario)
  - [Mitigations](#mitigations)
  - [Example](#example)
- [Race Condition](#race-condition)
  - [Contract.sol](#contractsol)
- [Race Condition](#race-condition-1)
  - [Attack Scenario](#attack-scenario-1)
  - [Mitigations](#mitigations-1)
- [Unchecked External Call](#unchecked-external-call)
  - [KingOfTheEtherThrone.sol](#kingoftheetherthronesol)
  - [Attack](#attack)
  - [Mitigation](#mitigation)
  - [Example](#example-1)
  - [References](#references)
- [Forced Ether Reception](#forced-ether-reception)
  - [Coin.sol](#coinsol)
- [Contracts can be forced to receive ether](#contracts-can-be-forced-to-receive-ether)
  - [Attack Scenario](#attack-scenario-2)
  - [Example](#example-2)
  - [Mitigations](#mitigations-2)
  - [References](#references-1)
- [Unprotected function](#unprotected-function)
  - [Unprotected.sol](#unprotectedsol)
- [Unprotected function](#unprotected-function-1)
  - [Attack Scenario](#attack-scenario-3)
  - [Mitigations](#mitigations-3)
  - [Examples](#examples)

# Incorrect interface

## Alice.sol

```js
contract Alice {
    int public val;

    function set(int new_val){
        val = new_val;
    }

    function set_fixed(int new_val){
        val = new_val;
    }

    function(){
        val = 1;
    }
}
```

## Bob.sol

```js
abstract contract Alice {
    function set(uint) public virtual;
    function set_fixed(int) public virtual;
}

contract Bob {
    function set(Alice c) public{
        c.set(42);
    }

    function set_fixed(Alice c) public{
        c.set_fixed(42);
    }
}
```

# Incorrect interface

A contract interface defines functions with a different type signature than the implementation, causing two different method id's to be created.
As a result, when the interfact is called, the fallback method will be executed.

## Attack Scenario

- The interface is incorrectly defined. `Alice.set(uint)` takes an `uint` in `Bob.sol` but `Alice.set(int)` a `int` in `Alice.sol`. The two interfaces will produce two differents method IDs. As a result, Bob will call the fallback function of Alice rather than of `set`.

## Mitigations

Verify that type signatures are identical between inferfaces and implementations.

## Example

We now walk through how to find this vulnerability in the [Alice](#Alice.sol) and [Bob](#Bob.sol) contracts in this repo.

First, get the bytecode and the abi of the contracts:

```̀bash
$ solc --bin Alice.sol
6060604052341561000f57600080fd5b5b6101158061001f6000396000f300606060405236156051576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680633c6bb436146067578063a5d5e46514608d578063e5c19b2d1460ad575b3415605b57600080fd5b5b60016000819055505b005b3415607157600080fd5b607760cd565b6040518082815260200191505060405180910390f35b3415609757600080fd5b60ab600480803590602001909190505060d3565b005b341560b757600080fd5b60cb600480803590602001909190505060de565b005b60005481565b806000819055505b50565b806000819055505b505600a165627a7a723058207d0ad6d1ce356adf9fa0284c9f887bb4b912204886b731c37c2ae5d16aef19a20029
$ solc --abi Alice.sol
[{"constant":true,"inputs":[],"name":"val","outputs":[{"name":"","type":"int256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"new_val","type":"int256"}],"name":"set_fixed","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"new_val","type":"int256"}],"name":"set","outputs":[],"payable":false,"type":"function"},{"payable":false,"type":"fallback"}]


$ solc --bin Bob.sol
6060604052341561000f57600080fd5b5b6101f58061001f6000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680632801617e1461004957806390b2290e14610082575b600080fd5b341561005457600080fd5b610080600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919050506100bb565b005b341561008d57600080fd5b6100b9600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610142565b005b8073ffffffffffffffffffffffffffffffffffffffff166360fe47b1602a6040518263ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040180828152602001915050600060405180830381600087803b151561012a57600080fd5b6102c65a03f1151561013b57600080fd5b5050505b50565b8073ffffffffffffffffffffffffffffffffffffffff1663a5d5e465602a6040518263ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040180828152602001915050600060405180830381600087803b15156101b157600080fd5b6102c65a03f115156101c257600080fd5b5050505b505600a165627a7a72305820f8c9dcade78d92097c18627223a8583507e9331ef1e5de02640ffc2e731111320029
$ solc --abi Bob.sol
[{"constant":false,"inputs":[{"name":"c","type":"address"}],"name":"set","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"c","type":"address"}],"name":"set_fixed","outputs":[],"payable":false,"type":"function"}]
```

The following commands were tested on a private blockchain

```javascript
$ get attach

// this unlock the account for a limited amount of time
// if you have an error:
// Error: authentication needed: password or unlock
// you can to call unlockAccount again
personal.unlockAccount(eth.accounts[0], "apasswordtochange")

var bytecodeAlice = '0x6060604052341561000f57600080fd5b5b6101158061001f6000396000f300606060405236156051576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680633c6bb436146067578063a5d5e46514608d578063e5c19b2d1460ad575b3415605b57600080fd5b5b60016000819055505b005b3415607157600080fd5b607760cd565b6040518082815260200191505060405180910390f35b3415609757600080fd5b60ab600480803590602001909190505060d3565b005b341560b757600080fd5b60cb600480803590602001909190505060de565b005b60005481565b806000819055505b50565b806000819055505b505600a165627a7a723058207d0ad6d1ce356adf9fa0284c9f887bb4b912204886b731c37c2ae5d16aef19a20029'
var abiAlice = [{"constant":true,"inputs":[],"name":"val","outputs":[{"name":"","type":"int256"}],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"new_val","type":"int256"}],"name":"set_fixed","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"new_val","type":"int256"}],"name":"set","outputs":[],"payable":false,"type":"function"},{"payable":false,"type":"fallback"}]

var bytecodeBob = '0x6060604052341561000f57600080fd5b5b6101f58061001f6000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680632801617e1461004957806390b2290e14610082575b600080fd5b341561005457600080fd5b610080600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919050506100bb565b005b341561008d57600080fd5b6100b9600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610142565b005b8073ffffffffffffffffffffffffffffffffffffffff166360fe47b1602a6040518263ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040180828152602001915050600060405180830381600087803b151561012a57600080fd5b6102c65a03f1151561013b57600080fd5b5050505b50565b8073ffffffffffffffffffffffffffffffffffffffff1663a5d5e465602a6040518263ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040180828152602001915050600060405180830381600087803b15156101b157600080fd5b6102c65a03f115156101c257600080fd5b5050505b505600a165627a7a72305820f8c9dcade78d92097c18627223a8583507e9331ef1e5de02640ffc2e731111320029'
var abiBob = [{"constant":false,"inputs":[{"name":"c","type":"address"}],"name":"set","outputs":[],"payable":false,"type":"function"},{"constant":false,"inputs":[{"name":"c","type":"address"}],"name":"set_fixed","outputs":[],"payable":false,"type":"function"}]

var contractAlice = eth.contract(abiAlice);
var txDeployAlice = {from:eth.coinbase, data: bytecodeAlice, gas: 1000000};
var contractPartialInstanceAlice = contractAlice.new(txDeployAlice);

// Wait to mine the block containing the transaction

var alice = contractAlice.at(contractPartialInstanceAlice.address);

var contractBob = eth.contract(abiBob);
var txDeployBob = {from:eth.coinbase, data: bytecodeBob, gas: 1000000};
var contractPartialInstanceBob = contractBob.new(txDeployBob);

// Wait to mine the block containing the transaction

var bob = contractBob.at(contractPartialInstanceBob.address);

// From now, wait for each transaction to be mined before calling
// the others transactions

// print the default value of val: 0
alice.val()

// call bob.set, as the interface is wrong, it will call
// the fallback function of alice
bob.set(alice.address, {from: eth.accounts[0]} )
// print val: 1
alice.val()

// call the fixed version of the interface
bob.set_fixed(alice.address, {from: eth.accounts[0]} )
// print val: 42
alice.val()
```

# Race Condition

## Contract.sol

```js
interface ERC20 {
    function totalSupply() external  returns (uint);
    function balanceOf(address _owner) external  returns (uint);
    function transfer(address _to, uint _value) external  returns (bool);
    function transferFrom(address _from, address _to, uint _value) external  returns (bool);
    function approve(address _spender, uint _value) external  returns (bool);
    function allowance(address _owner, address _spender) external  returns (uint);
    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);
}

contract RaceCondition{
    address private owner;
    uint public price;
    ERC20 token;

    constructor(uint _price, ERC20 _token)
        public
    {
        owner = msg.sender;
        price = _price;
        token = _token;
    }

    // If the owner sees someone calls buy
    // he can call changePrice to set a new price
    // If his transaction is mined first, he can
    // receive more tokens than excepted by the new buyer
    function buy(uint new_price) payable
        public
    {
        require(msg.value >= price);

        // we assume that the RaceCondition contract
        // has enough allowance
        token.transferFrom(msg.sender, owner, price);

        price = new_price;
        owner = msg.sender;
    }

    function changePrice(uint new_price) public{
        require(msg.sender == owner);
        price = new_price;
    }

}
```

# Race Condition

There is a gap between the creation of a transaction and the moment it is accepted in the blockchain.
Therefore, an attacker can take advantage of this gap to put a contract in a state that advantages them.

## Attack Scenario

- Bob creates `RaceCondition(100, token)`. Alice trusts `RaceCondition` with all its tokens. Alice calls `buy(150)`
  Bob sees the transaction, and calls `changePrice(300)`. The transaction of Bob is mined before the one of Alice and
  as a result, Bob received 300 tokens.

- The ERC20 standard's `approve` and `transferFrom` functions are vulnerable to a race condition. Suppose Alice has
  approved Bob to spend 100 tokens on her behalf. She then decides to only approve him for 50 tokens and sends
  a second `approve` transaction. However, Bob sees that he's about to be downgraded and quickly submits a
  `transferFrom` for the original 100 tokens he was approved for. If this transaction gets mined before Alice's
  second `approve`, Bob will be able to spend 150 of Alice's tokens.

## Mitigations

- For the ERC20 bug, insist that Alice only be able to `approve` Bob when he is approved for 0 tokens.
- Keep in mind that all transactions may be front-run

# Unchecked External Call

## KingOfTheEtherThrone.sol

```js
// A chain-game contract that maintains a 'throne' which agents may pay to rule.
// See www.kingoftheether.com & https://github.com/kieranelby/KingOfTheEtherThrone .
// (c) Kieran Elby 2016. All rights reserved.
// v0.4.0.
// Inspired by ethereumpyramid.com and the (now-gone?) "magnificent bitcoin gem".

// This contract lives on the blockchain at 0xb336a86e2feb1e87a328fcb7dd4d04de3df254d0
// and was compiled (using optimization) with:
// Solidity version: 0.2.1-fad2d4df/.-Emscripten/clang/int linked to libethereum

// For future versions it would be nice to ...
// TODO - enforce time-limit on reign (can contracts do that without external action)?
// TODO - add a random reset?
// TODO - add bitcoin bridge so agents can pay in bitcoin?
// TODO - maybe allow different return payment address?

contract KingOfTheEtherThrone {

    struct Monarch {
        // Address to which their compensation will be sent.
        address etherAddress;
        // A name by which they wish to be known.
        // NB: Unfortunately "string" seems to expose some bugs in web3.
        string name;
        // How much did they pay to become monarch?
        uint claimPrice;
        // When did their rule start (based on block.timestamp)?
        uint coronationTimestamp;
    }

    // The wizard is the hidden power behind the throne; they
    // occupy the throne during gaps in succession and collect fees.
    address wizardAddress;

    // Used to ensure only the wizard can do some things.
    modifier onlywizard { if (msg.sender == wizardAddress) _; }

    // How much must the first monarch pay?
    uint constant startingClaimPrice = 100 finney;

    // The next claimPrice is calculated from the previous claimFee
    // by multiplying by claimFeeAdjustNum and dividing by claimFeeAdjustDen -
    // for example, num=3 and den=2 would cause a 50% increase.
    uint constant claimPriceAdjustNum = 3;
    uint constant claimPriceAdjustDen = 2;

    // How much of each claimFee goes to the wizard (expressed as a fraction)?
    // e.g. num=1 and den=100 would deduct 1% for the wizard, leaving 99% as
    // the compensation fee for the usurped monarch.
    uint constant wizardCommissionFractionNum = 1;
    uint constant wizardCommissionFractionDen = 100;

    // How much must an agent pay now to become the monarch?
    uint public currentClaimPrice;

    // The King (or Queen) of the Ether.
    Monarch public currentMonarch;

    // Earliest-first list of previous throne holders.
    Monarch[] public pastMonarchs;

    // Create a new throne, with the creator as wizard and first ruler.
    // Sets up some hopefully sensible defaults.
     constructor() public {
        wizardAddress = msg.sender;
        currentClaimPrice = startingClaimPrice;
        currentMonarch = Monarch(
            wizardAddress,
            "[Vacant]",
            0,
            block.timestamp
        );
    }

    function numberOfMonarchs() public returns (uint n) {
        return pastMonarchs.length;
    }

    // Fired when the throne is claimed.
    // In theory can be used to help build a front-end.
    event ThroneClaimed(
        address usurperEtherAddress,
        string usurperName,
        uint newClaimPrice
    );

    // Fallback function - simple transactions trigger this.
    // Assume the message data is their desired name.
    fallback() external {
        claimThrone(string(msg.data));
    }

    // Claim the throne for the given name by paying the currentClaimFee.
    function claimThrone(string memory name) public payable {

        uint valuePaid = msg.value;

        // If they paid too little, reject claim and refund their money.
        if (valuePaid < currentClaimPrice) {
            msg.sender.send(valuePaid);
            return;
        }

        // If they paid too much, continue with claim but refund the excess.
        if (valuePaid > currentClaimPrice) {
            uint excessPaid = valuePaid - currentClaimPrice;
            msg.sender.send(excessPaid);
            valuePaid = valuePaid - excessPaid;
        }

        // The claim price payment goes to the current monarch as compensation
        // (with a commission held back for the wizard). We let the wizard's
        // payments accumulate to avoid wasting gas sending small fees.

        uint wizardCommission = (valuePaid * wizardCommissionFractionNum) / wizardCommissionFractionDen;

        uint compensation = valuePaid - wizardCommission;

        if (currentMonarch.etherAddress != wizardAddress) {
            payable(currentMonarch.etherAddress).send(compensation);
        } else {
            // When the throne is vacant, the fee accumulates for the wizard.
        }

        // Usurp the current monarch, replacing them with the new one.
        pastMonarchs.push(currentMonarch);
        currentMonarch = Monarch(
            msg.sender,
            name,
            valuePaid,
            block.timestamp
        );

        // Increase the claim fee for next time.
        // Stop number of trailing decimals getting silly - we round it a bit.
        uint rawNewClaimPrice = currentClaimPrice * claimPriceAdjustNum / claimPriceAdjustDen;
        if (rawNewClaimPrice < 10 finney) {
            currentClaimPrice = rawNewClaimPrice;
        } else if (rawNewClaimPrice < 100 finney) {
            currentClaimPrice = 100 szabo * (rawNewClaimPrice / 100 szabo);
        } else if (rawNewClaimPrice < 1 ether) {
            currentClaimPrice = 1 finney * (rawNewClaimPrice / 1 finney);
        } else if (rawNewClaimPrice < 10 ether) {
            currentClaimPrice = 10 finney * (rawNewClaimPrice / 10 finney);
        } else if (rawNewClaimPrice < 100 ether) {
            currentClaimPrice = 100 finney * (rawNewClaimPrice / 100 finney);
        } else if (rawNewClaimPrice < 1000 ether) {
            currentClaimPrice = 1 ether * (rawNewClaimPrice / 1 ether);
        } else if (rawNewClaimPrice < 10000 ether) {
            currentClaimPrice = 10 ether * (rawNewClaimPrice / 10 ether);
        } else {
            currentClaimPrice = rawNewClaimPrice;
        }

        // Hail the new monarch!
        emit ThroneClaimed(currentMonarch.etherAddress, currentMonarch.name, currentClaimPrice);
    }

    // Used only by the wizard to collect his commission.
    function sweepCommission(uint amount) public onlywizard {
        payable(wizardAddress).send(amount);
    }

    // Used only by the wizard to collect his commission.
    function transferOwnership(address newOwner) public onlywizard {
        wizardAddress = newOwner;
    }

}
```

Certain Solidity operations known as "external calls", require the developer to manually ensure that the operation succeeded. This is in contrast to operations which throw an exception on failure. If an external call fails, but is not checked, the contract will continue execution as if the call succeeded. This will likely result in buggy and potentially exploitable behavior from the contract.

## Attack

- A contract uses an unchecked `address.send()` external call to transfer Ether.
- If it transfers Ether to an attacker contract, the attacker contract can reliably cause the external call to fail, for example, with a fallback function which intentionally runs out of gas.
- The consequences of this external call failing will be contract specific. - In the case of the King of the Ether contract, this resulted in accidental loss of Ether for some contract users, due to refunds not being sent.

## Mitigation

- Manually perform validation when making external calls
- Use `address.transfer()`

## Example

- [King of the Ether](https://www.kingoftheether.com/postmortem.html) (line numbers:
  [100](KotET_source_code/KingOfTheEtherThrone.sol#L100),
  [107](KotET_source_code/KingOfTheEtherThrone.sol#L107),
  [120](KotET_source_code/KingOfTheEtherThrone.sol#L120),
  [161](KotET_source_code/KingOfTheEtherThrone.sol#L161))

## References

- http://solidity.readthedocs.io/en/develop/security-considerations.html
- http://solidity.readthedocs.io/en/develop/types.html#members-of-addresses
- https://github.com/ConsenSys/smart-contract-best-practices#handle-errors-in-external-calls
- https://vessenes.com/ethereum-griefing-wallets-send-w-throw-considered-harmful/

# Forced Ether Reception

## Coin.sol

```js
contract owned {
    address public owner;

     constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes calldata _extraData) external; }

contract TokenERC20 {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This generates a public event on the blockchain that will notify clients
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        string memory tokenName,
        string memory tokenSymbol
    ) public {
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal virtual {
        // Prevent transfer to 0x0 address.
        require(_to != address(0));
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` in behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes memory _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, address(this), _extraData);
            return true;
        }
    }

}

/******************************************/
/*       ADVANCED TOKEN STARTS HERE       */
/******************************************/

contract MyAdvancedToken is owned, TokenERC20 {

    mapping (address => bool) public frozenAccount;

    /* This generates a public event on the blockchain that will notify clients */
    event FrozenFunds(address target, bool frozen);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor(
        string memory tokenName,
        string memory tokenSymbol
    ) TokenERC20(tokenName, tokenSymbol) public {}

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal override{
        require (_to != address(0));                               // Prevent transfer to 0x0 address.
        require (balanceOf[_from] >= _value);               // Check if the sender has enough
        require (balanceOf[_to] + _value >= balanceOf[_to]); // Check for overflows
        require(!frozenAccount[_from]);                     // Check if sender is frozen
        require(!frozenAccount[_to]);                       // Check if recipient is frozen
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        emit Transfer(_from, _to, _value);
    }

    /// @notice Buy tokens from contract by sending ether
    function buy() payable public {
        uint amount = msg.value;                          // calculates the amount
	balanceOf[msg.sender] += amount;                  // updates the balance
        totalSupply += amount;                            // updates the total supply
        _transfer(address(0x0), msg.sender, amount);      // makes the transfer
    }

    /* Migration function */
    function migrate_and_destroy() public onlyOwner {
	assert(address(this).balance == totalSupply);                 // consistency check
	selfdestruct(payable(owner));                                      // transfer the ether to the owner and kill the contract
    }
}
```

# Contracts can be forced to receive ether

In certain circunstances, contracts can be forced to receive ether without triggering any code. This should be considered by the contract developers in order to avoid breaking important invariants in their code.

## Attack Scenario

An attacker can use a specially crafted contract to forceful send ether using `suicide` / `selfdestruct`:

```solidity
contract Sender {
  function receive_and_suicide(address target) payable {
    suicide(target);
  }
}
```

## Example

- The MyAdvancedToken contract in [coin.sol](coin.sol#L145) is vulnerable to this attack. It will stop the owner to perform the migration of the contract.

## Mitigations

There is no way to block the reception of ether. The only mitigation is to avoid assuming how the balance of the contract
increases and implement checks to handle this type of edge cases.

## References

- https://solidity.readthedocs.io/en/develop/security-considerations.html#sending-and-receiving-ether

# Unprotected function

## Unprotected.sol

```js
contract Unprotected{
    address private owner;

    modifier onlyowner {
        require(msg.sender==owner);
        _;
    }

    constructor()
        public
    {
        owner = msg.sender;
    }

    // This function should be protected
    function changeOwner(address _newOwner)
        public
    {
       owner = _newOwner;
    }

    function changeOwner_fixed(address _newOwner)
        public
        onlyowner
    {
       owner = _newOwner;
    }
}
```

# Unprotected function

Missing (or incorrectly used) modifier on a function allows an attacker to use sensitive functionality in the contract.

## Attack Scenario

A contract with a `changeOwner` function does not label it as `private` and therefore
allows anyone to become the contract owner.

## Mitigations

Always specify a modifier for functions.

## Examples

- An `onlyOwner` modifier is [defined but not used](#Unprotected.sol), allowing anyone to become the `owner`
- April 2016: [Rubixi allows anyone to become owner](https://etherscan.io/address/0xe82719202e5965Cf5D9B6673B7503a3b92DE20be#code)
- July 2017: [Parity Wallet](https://blog.zeppelin.solutions/on-the-parity-wallet-multisig-hack-405a8c12e8f7). For code, see [initWallet](WalletLibrary_source_code/WalletLibrary.sol)
- BitGo Wallet v2 allows anyone to call tryInsertSequenceId. If you try close to MAXINT, no further transactions would be allowed. [Fix: make tryInsertSequenceId private.](https://github.com/BitGo/eth-multisig-v2/commit/8042188f08c879e06f097ae55c140e0aa7baaff8#diff-b498cc6fd64f83803c260abd8de0a8f5)
- Feb 2020: [Nexus Mutual's Oraclize callback was unprotected—allowing anyone to call it.](https://medium.com/nexus-mutual/responsible-vulnerability-disclosure-ece3fe3bcefa) Oraclize triggers a rebalance to occur via Uniswap.
