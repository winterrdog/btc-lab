# Week 2: Send A Multisig Transaction

Challenge: extend your wallet program to spend your own coins. You will create
two transactions: one that spends from a key-path `p2tr` and funds a script-path `p2tr`
multisig, and a second transaction that spends from that multisig. You will
sign and broadcast both transactions to the signet network, and submit your code
that gnerates both transactions as hex-encoded strings.

You may copy-and-paste as much code from last week as needed, or package multiple
source code files together as long as the program works.

We will evaluate your code submission against the transactions in the signet chain
and again, use of the Bitcoin Core wallet is not allowed by your submitted code.

## Steps

1. Re-run last week's code to recover wallet state: 2000 key pairs, and all unspent coins
2. Create a 2-of-2 multisig script from the first two keys (indexes 0 & 1)
3. Compute the [tap tree and `p2tr` witness program](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#user-content-Constructing_and_spending_Taproot_outputs) from that script
4. Construct the first transaction (spend from key-path `p2tr`):
    1. Choose one of your unspent coins for the input
    2. Add an output: 0.01 BTC output to your multisig witness program
    3. Another output: the change (minus fee!) back to your 0th key's key-path `p2tr` program
    4. Compute the `SIGHASH_ALL` transaction digest for your input as specified in [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#user-content-Common_signature_message)
    5. Sign the digest using the key responsible for the coin you are spending
    6. Create a transaction witness with the signature and public key
    7. Serialize the transaction (without witness data!) and compute the txid
    8. Serialize the final complete transaction
    9. Return both the txid (required to spend from the script-path `p2tr`) and the complete hex-encoded transaction.
5. Construct the second transaction (spend from script-path `p2tr`):
    1. Repeat the previous steps but spend the script-path `p2tr` multisig output you created in the last transaction as the input to the new transaction
    2. Send 0 BTC to an `OP_RETURN` output script which encodes your full name (or nym) in ASCII
    3. Don't forget the change output and fee! You can reuse your 0th key like before.
    4. Serialize the final transaction and return the hex encoded string.

## Show off

While not mandatory, you are encouraged to broadcast your transactions to the
signet network! You can use `bitcoin-cli -signet sendrawtransaction <hex>` for
this. It will be very cool to see everyone's name in our private signet blockchain!

## Submission

This assignment is a continuation of [Recover Balance](./recover_balance.md)
which you must have completed already to continue. You can copy files from your Recover Balance
repo to pass the new autograder test, which is executed by [solution/run_spend.sh](solution/run_spend.sh).
So, like last week, if you need to install additional packages for your project
you can modify that script.

> [!TIP]
> Even though the Spend challenge relies on code you wrote for Balance,
> you MUST use this new, separate repo for the the Spend code.

You code must return exactly TWO lines, each line containing the raw hex string
for a valid transaction. (see the [example](#example-output) below).

The autograder will again run in an environment with a signet node that is stuck
on block 400. We do this so that even if you have already spent your coins and submitted
your transactions to the signet network, the autograder node will NOT process those
transactions and they can be evaluated again locally! Both transactions must be
accepted to the autograder node's mempool to pass.

Like last week, the default language is Python and an obfuscated code template
is yours to play with in [solution/python/spend.py](solution/python/spend.py).
If you choose to write in a different language you MUST edit [solution/run_spend.sh](solution/run_spend.sh).

There is also a Rust template in [solution/rust/spend/src](solution/rust/spend/src).
If you choose to work in Rust you will need to modify [solution/run_spend.sh](solution/run_spend.sh)
to execute the Rust code.

You **MAY** import an ECDSA library to access constants like `G` or the order
of the curve, and you **MAY** use an external library for message signing (although
we encourage you to implement ECDSA signing yourself!). You **MAY NOT** use a
Bitcoin-specific library to avoid implementing BIP32 or structuring transaction
objects yourself.

## Hints

- [BIP 342: Validation of Taproot Scripts](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
- [BIP 141: Segregated Witness (Consensus layer)](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
- [BIP 143: Transaction Signature Verification for Version 0 Witness Program](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
- [Bitcoin protocol TX serialization](https://en.bitcoin.it/wiki/Protocol_documentation#tx)
- When constructing a multisig script use `OP_2` (not `0x02`) to indicate the number of required signatures and keys
- Other data like public keys must be pushed to the stack with length bytes (e.g. `0x21` for a 33-byte compressed public key)
- For our purposes, all input sequences are `0xffffffff` and all transaction locktimes are `0x00000000`
- Since we are only concerned with segregated witness transactions, input `scriptSig` will always be empty (`0x00`, a 0-length script)
- The `scriptcode` in the transaction commitment must be prefixed with a length byte, but the witness program only commits to the raw script with no length byte

## Example output

```sh
# My wallet descriptor is
# wallet_000: tr(tprv8ZgxMBicQKsPePwbSC93GebdF8eNz2qkn7fxfGhNwJCyh2R6XKd7tyUs1wsyZSVfHYLL9g4aLy8LRrJhSUhkTHsAUY1WU2SDg2Sx6yS9TLj/86h/1h/0h/0/*)#uuj8klsl
$ python spend_solution.py
02000000000101306270bb4c0356392835a1867883d858a708523a17254e8683e1a55f83eb4e42fe00000000ffffffff0240420f000000000022512083b591cd94083108f40e0b99fdfb2ed5ff5de7142049b4ba82bc8398247a5c06020e3d00000000002251205b70323aaba93c308dee73e80c0090134d281e20899fecc1fa696e56ccd8f747014079fa36e05feb4816633728e8fcb1dd222e728b413df161b366d93f3e0cb1c92bd5ddf18821bc56f66473555706bd246eaa637390996b4ee1a11ef41c161abcef00000000
020000000001015e3ce275f299bf374fec2718c5d38846ddd85bfea46219d817e5450a28d28e620000000000ffffffff0200000000000000000b6a0970696e686561646d7a583e0f00000000002251205b70323aaba93c308dee73e80c0090134d281e20899fecc1fa696e56ccd8f7470440acfb049cb922ffea30cd2ce17667a1121d4c47c1c95e1eb69d4772ae6e1d0cd33aeefadf73ac62f744c164816ba957d67b977978b00b0ba6fae8224c0b8bdd8840d95ca2fd121b9c85e44596b3c880c866b564757d9c9f538628bb44b7b07d98a76ba7ac99fe7d5566aeb8a55639cdc36e770e6695a9d62434ef190a4951215a15470020e6e1296d0ae3d14050d755b4e07414544e0dd0e290497b48bc0f5fe7b9193e99ba20d0ac7c722cd2c8ee4ea94ea86e3f67ad59dfaf1b2758bb8826eb8910b82861dbba528721c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac000000000
```

The transactions generated in this example can be decoded by RPC:

### Spend from `p2tr` key-path to `p2tr` script-path multisig

```sh
$  bitcoin-cli decoderawtransaction 02000000000101306270bb4c0356392835a1867883d858a708523a17254e8683e1a55f83eb4e42fe00000000ffffffff0240420f000000000022512083b591cd94083108f40e0b99fdfb2ed5ff5de7142049b4ba82bc8398247a5c06020e3d00000000002251205b70323aaba93c308dee73e80c0090134d281e20899fecc1fa696e56ccd8f747014079fa36e05feb4816633728e8fcb1dd222e728b413df161b366d93f3e0cb1c92bd5ddf18821bc56f66473555706bd246eaa637390996b4ee1a11ef41c161abcef00000000

{
  "txid": "628ed2280a45e517d81962a4fe5bd8dd4688d3c51827ec4f37bf99f275e23c5e",
  "hash": "0854cb878bb33cbc3f59a94560d41a9ee7da43420a4d56094f28e66711fe2fc6",
  "version": 2,
  "size": 205,
  "vsize": 154,
  "weight": 616,
  "locktime": 0,
  "vin": [
    {
      "txid": "424eeb835fa5e183864e25173a5208a758d8837886a135283956034cbb706230",
      "vout": 254,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "79fa36e05feb4816633728e8fcb1dd222e728b413df161b366d93f3e0cb1c92bd5ddf18821bc56f66473555706bd246eaa637390996b4ee1a11ef41c161abcef"
      ],
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "value": 0.01000000,
      "n": 0,
      "scriptPubKey": {
        "asm": "1 83b591cd94083108f40e0b99fdfb2ed5ff5de7142049b4ba82bc8398247a5c06",
        "desc": "rawtr(83b591cd94083108f40e0b99fdfb2ed5ff5de7142049b4ba82bc8398247a5c06)#v7zanhk5",
        "hex": "512083b591cd94083108f40e0b99fdfb2ed5ff5de7142049b4ba82bc8398247a5c06",
        "address": "bcrt1psw6ernv5pqcs3aqwpwvlm7ew6hl4mec5ypymfw5zhjpesfr6tsrq4x9mqn",
        "type": "witness_v1_taproot"
      }
    },
    {
      "value": 0.04001282,
      "n": 1,
      "scriptPubKey": {
        "asm": "1 5b70323aaba93c308dee73e80c0090134d281e20899fecc1fa696e56ccd8f747",
        "desc": "rawtr(5b70323aaba93c308dee73e80c0090134d281e20899fecc1fa696e56ccd8f747)#v72vqqpf",
        "hex": "51205b70323aaba93c308dee73e80c0090134d281e20899fecc1fa696e56ccd8f747",
        "address": "bcrt1ptdcryw4t4y7rpr0ww05qcqyszdxjs83q3x07es06d9h9dnxc7ars6ry8zd",
        "type": "witness_v1_taproot"
      }
    }
  ]
}

```

### Spend from `p2tr` script-path to `OP_RETURN`

```sh
$  bitcoin-cli decoderawtransaction 020000000001015e3ce275f299bf374fec2718c5d38846ddd85bfea46219d817e5450a28d28e620000000000ffffffff0200000000000000000b6a0970696e686561646d7a583e0f00000000002251205b70323aaba93c308dee73e80c0090134d281e20899fecc1fa696e56ccd8f7470440acfb049cb922ffea30cd2ce17667a1121d4c47c1c95e1eb69d4772ae6e1d0cd33aeefadf73ac62f744c164816ba957d67b977978b00b0ba6fae8224c0b8bdd8840d95ca2fd121b9c85e44596b3c880c866b564757d9c9f538628bb44b7b07d98a76ba7ac99fe7d5566aeb8a55639cdc36e770e6695a9d62434ef190a4951215a15470020e6e1296d0ae3d14050d755b4e07414544e0dd0e290497b48bc0f5fe7b9193e99ba20d0ac7c722cd2c8ee4ea94ea86e3f67ad59dfaf1b2758bb8826eb8910b82861dbba528721c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac000000000
{
  "txid": "a32c20e0b4be4be951027618058c585d97d3a42a630505a5312ccc9e9950347a",
  "hash": "cac3922186430946f9be02ef869c08a504c88e75e6ac3601fbe60d308623a096",
  "version": 2,
  "size": 353,
  "vsize": 174,
  "weight": 695,
  "locktime": 0,
  "vin": [
    {
      "txid": "628ed2280a45e517d81962a4fe5bd8dd4688d3c51827ec4f37bf99f275e23c5e",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "txinwitness": [
        "acfb049cb922ffea30cd2ce17667a1121d4c47c1c95e1eb69d4772ae6e1d0cd33aeefadf73ac62f744c164816ba957d67b977978b00b0ba6fae8224c0b8bdd88",
        "d95ca2fd121b9c85e44596b3c880c866b564757d9c9f538628bb44b7b07d98a76ba7ac99fe7d5566aeb8a55639cdc36e770e6695a9d62434ef190a4951215a15",
        "0020e6e1296d0ae3d14050d755b4e07414544e0dd0e290497b48bc0f5fe7b9193e99ba20d0ac7c722cd2c8ee4ea94ea86e3f67ad59dfaf1b2758bb8826eb8910b82861dbba5287",
        "c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
      ],
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "value": 0.00000000,
      "n": 0,
      "scriptPubKey": {
        "asm": "OP_RETURN 70696e686561646d7a",
        "desc": "raw(6a0970696e686561646d7a)#jfe73c25",
        "hex": "6a0970696e686561646d7a",
        "type": "nulldata"
      }
    },
    {
      "value": 0.00999000,
      "n": 1,
      "scriptPubKey": {
        "asm": "1 5b70323aaba93c308dee73e80c0090134d281e20899fecc1fa696e56ccd8f747",
        "desc": "rawtr(5b70323aaba93c308dee73e80c0090134d281e20899fecc1fa696e56ccd8f747)#v72vqqpf",
        "hex": "51205b70323aaba93c308dee73e80c0090134d281e20899fecc1fa696e56ccd8f747",
        "address": "bcrt1ptdcryw4t4y7rpr0ww05qcqyszdxjs83q3x07es06d9h9dnxc7ars6ry8zd",
        "type": "witness_v1_taproot"
      }
    }
  ]
}

```

### Test transaction validity

Result of RPC `testmempoolaccept` with both transactions:

```
[
  {
    "txid": "7d6ea4e7e0ec149302d55feefaa1cb740d89668d2a7768bfe7b56f2dfd4c3a37",
    "wtxid": "3cdda17dd342d54c3926869c2ae4a4086f31b476c1466f484eed25260f14fca0",
    "allowed": true,
    "vsize": 154,
    "fees": {
      "base": 0.00001000,
      "effective-feerate": 0.00006493,
      "effective-includes": [
        "3cdda17dd342d54c3926869c2ae4a4086f31b476c1466f484eed25260f14fca0"
      ]
    }
  },
  {
    "txid": "a051150e63c66df16c967141e205a8d474fa00322612629d54805ad649bd177a",
    "wtxid": "13f1fb4fb54c9ea57d9ab242cc64dff352146dd6d2083ae0176d8771ee12dd12",
    "allowed": true,
    "vsize": 174,
    "fees": {
      "base": 0.00001000,
      "effective-feerate": 0.00005747,
      "effective-includes": [
        "13f1fb4fb54c9ea57d9ab242cc64dff352146dd6d2083ae0176d8771ee12dd12"
      ]
    }
  }
]

```
