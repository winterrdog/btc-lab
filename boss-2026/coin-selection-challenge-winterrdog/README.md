# Coin Selection Challenge

The goal of this challenge is to construct an algorithm that chooses spendable
UTXOs from a wallet's coin pool to fund a transaction with specific requirements.
Those requirements are:
- An output (a destination address and value)
- A fee rate in [BTC/kvB](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch09_fees.adoc#fees-and-fee-rates)

## Example:

Imagine you have three spendable UTXOs and you need to send 1 BTC at a fee rate of
0.00001 BTC/kvB (aka 1 sat/vB). Your algorithm must choose which UTXOs to spend as
inputs to the transaction, add the required output, and then (maybe) add a change output.

To be valid, your transaction MUST HAVE:
- Total input value > total output value
- Fee rate >= required minimum fee rate
    - fee rate = (total input value - total output value) / virtual transaction size
    - Transaction weight ("weight units") and virtual transaction size ("vBytes") are defined in [BIP 141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#transaction-size-calculations)

If you look at the three spendable UTXOs below it should be obvious that only two
of them have a large enough value to fund our transaction, including the output amount
and whatever fee we intend to pay. But notice that the scriptPubKeys are different.
One UTXO is `p2wpkh` and the other is `p2tr`. Those require different witness
data when spending, which result in [different size transactions.](https://bitcoin.stackexchange.com/a/84006/3667)

That means that even if the fee rate is fixed, the amount of Bitcoin spent on the
fee depends on which UTXO you choose to spend. In other words, the nominal amount
of satoshis required to hit a target fee rate will depend on the virtual size
of the transaction, and therefore depend on the type of the inputs.

### Transaction requirements
```
  {
    "address": "bcrt1pqxgl52gtf85q2h9xqf4x60n2hcmzch8u20tpv9dtsa2yvwsgf07svg2aaf",
    "amount": "1.00003288",
    "rate": "0.00247765"
  }
```

### Wallet coin pool
```
[
  {
    "txid": "5c578bc5fbc2008621c47f590e388c96e345ffa774ad344de2e00ba233da2213",
    "vout": 46,
    "scriptPubKey": "5120e36157dd29da7444fc62398fe0725935000d8091d16ea28cf38ce26f19a4dff7",
    "amount": 1.59929134
  },
  {
    "txid": "5a6c11562d4d9ef0de2655beb1fbc607cd5c0ec8f0c758e70516e52736de320b",
    "vout": 396,
    "scriptPubKey": "00146c6333ea1a916d2a2db7a7a09e3ea1884643e0d9",
    "amount": 1.99870000
  },
  {
    "txid": "1546cd4a8d60290274154b337a3655021c940c13a053fbde619454149065b25f",
    "vout": 328,
    "scriptPubKey": "5120d2360557a23cf95c4a6bcdb036a952bc9e7cdfc3035690fea3131e799f5fb9c2",
    "amount": 0.99998136
  }
]
```

> [!TIP]
> A wallet may have a variety of UTXO types with a range of spending costs due to
their spending conditions, giving each a UTXO an "effective value" as a transaction
input. But block space is scarce! Confirmation speed is a marketplace
represented by dynamic fee rates. When fee rates are low, it might be the right
time to spend that big heavy expensive UTXO or even combine multiple UTXOs.
Sometimes you might not even need to "waste" vBytes with a change output at all!

## Assignment mechanics

You will work on a local regtest chain that has been generated in advance by
the challenge administrator (block data is committed to this repo in [`datadir/node0`](./datadir/node0)).

You will be given a wallet with a coin pool consisting of a variety of UTXO types.
You must create a wallet called `student` and import the descriptors generated
by the challenge administrator (committed to this repo in [`datadir/student_wallet.json`](./datadir/student_wallet.json)).

Finally you will be given an array of payments to make (committed to this repo in
[`payments.json`](./payments.json)). The fee rate of the payments in this timeline will change
over time! Your code will be expected to create valid transactions for every payment,
in the same order as the given array, at or above the given fee rate.

At the end of the timeline, your code MUST exit and the autograder will simply
examine your wallet's remaining balance and determine how much money you spent on fees.
**This will be your score.** Autograder will "pass" your submission if you create all the
required transactions, but the challenge administrators will evaluate your
work manually by comparing your score against a scale of benchmarks and the results
of your peers.

### Provided wallet tools

You only need to focus on coin selection for this assignment, so you will
be allowed access to a Bitcoin Core wallet with limited RPC functions.

> [!TIP]
> `-rpcuser=student`
> `-rpcpassword=boss2026`

This RPC user has permission ONLY for these commands:

- [`listunspent`](https://bitcoincore.org/en/doc/30.0.0/rpc/wallet/listunspent/) - get available coins
- [`getrawchangeaddress`](https://bitcoincore.org/en/doc/30.0.0/rpc/wallet/getrawchangeaddress/) - get a change address from your wallet
- [`createrawtransaction`](https://bitcoincore.org/en/doc/30.0.0/rpc/rawtransactions/createrawtransaction/) - serialize a transaction given a set of inputs and outputs
- [`signrawtransactionwithwallet`](https://bitcoincore.org/en/doc/30.0.0/rpc/wallet/signrawtransactionwithwallet/) - sign all inputs of a transaction
- [`sendrawtransaction`](https://bitcoincore.org/en/doc/30.0.0/rpc/rawtransactions/sendrawtransaction/) - send a final transaction to the network for confirmation

Also allowed:

- [`getbalances`](https://bitcoincore.org/en/doc/30.0.0/rpc/wallet/getbalances/)

- [`getblockcount`](https://bitcoincore.org/en/doc/30.0.0/rpc/blockchain/getblockcount/) - useful mainly to test API connection

- [`createwallet student false true`](https://bitcoincore.org/en/doc/30.0.0/rpc/wallet/createwallet/) - you must create a wallet with this name and
these parameters (`disable_private_keys=false`, `blank=true`)

- [`importdescriptors`](https://bitcoincore.org/en/doc/30.0.0/rpc/wallet/importdescriptors/) - import the private keys
for the wallet generated by the challenge administrator

- `generatetoaddress 1 bcrt1pqqqqrldkrl` - confirm your transaction so the
change outputs can be spent immediately. You MUST use this exact unspendable
address when creating new blocks or your code submission will fail
(you are not allowed to generate more coins for your own wallet). Every
transaction you create MUST be confirmed in a new block, and every new block
MUST only contain that one transaction (besides the coinbase).

> [!WARNING]
> All other RPC commands will be disabled by autograder.
> Attempting to use disabled commands will throw an error and fail.

### Start the local node

Assuming `bitcoind` is installed and available on your `$PATH`:

`bitcoind -datadir=$PWD/datadir/node0`

This will load the included `bitcoin.conf` file and `*.dat` block files. Your
code can make RPC calls to this node using the credentials given above:

```
$ bitcoin-cli -regtest -rpcuser=student -rpcpassword=boss2026 getblockcount
110
```

### Restart the node after running your code

As you work on your project you will likely need to reset to the initial state
of the blockchain. To do so, **stop your `bitcoind` process with `ctrl-c`** and then
restore the original, git-committed blockchain:

```
# delete new files (wallet, index, etc) created by Bitcoin
git clean -xdf datadir/
# restore blockchain to state in initial commit
git restore datadir/
```

This will wipe out your `student` wallet and any blocks and transactions you
had generated during the last run of your code.

> [!TIP]
> The code examples create a new "student" wallet which can only be done once.
> You will need to reset the `datadir` after every code execution whether or
> not any blocks have been generated.

## Submission

There are code templates available in the [`solution/`](./solution) directory
for Python and Rust. By default, the Python script will be tested. If you write
your solution in Rust (or any other language) you MUST modify
[`solution/run_coin_selection.sh`](./solution/run_coin_selection.sh).
That is the entrypoint script for autograder as well so if you need to add
any additional dependencies (i.e. `pip install...`) they must be added to that
script.

## Evaluation

Autograder will run your code and then examine the blockchain after your code exits.
Your submission will FAIL if:

- Any block generated by your code does not contain one transaction (plus the coinbase)
- The coinbase subsidy of any block generated by your code does not pay to `bcrt1pqqqqrldkrl`
- The payments in [`payments.json`](./payments.json) are not satisfied (address, amount, fee rate) and in the same order as the JSON file
- Your code crashes or quits with a non-zero exit code

Your score will simply be the amount of Bitcoin remaining in the `student` wallet.
We have tested the given data set enough to guarantee a solution is POSSIBLE. If
you are getting "insufficient funds" errors - your coin selection algorithm is bad!

> [!TIP]
> We may run your code against a DIFFERENT DATA SET for evaluation.
> We may change the wallet coin pool, `payments.json`, or BOTH.
> If you want to test your code against different data on your own
> you can examine the [`regtest-setup.py`](./regtest-setup.py) script.


