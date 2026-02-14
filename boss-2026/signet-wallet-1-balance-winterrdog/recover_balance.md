# Challenge 1: Recover Wallet State

Challenge: given a descriptor and a blockchain, compute your confirmed wallet
balance. Submit a program with your `tprv` hard-coded, execute the necessary
bitcoin-cli RPCs and return your wallet balance as a float with 8 decimal places.

We will run your program against Bitcoin Core synced to our private signet chain
but with the Bitcoin Core wallet *disabled*. That means that RPCs like
`importdescriptor` will fail. You are, of course, allowed to import your
descriptor into Bitcoin Core to check your own work as you develop the wallet locally.

## Steps

1. Decode the base58 `tprv` and extract the private key and chaincode
2. Derive the key and chaincode at the path in the descriptor (`86h/1h/0h/0`)
3. Derive 2000 private keys from that path
4. Compute the compressed [BIP340 public key](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) for each private key
5. Compute the `p2tr` witness program for each public key based on the [`tr()` descriptor specification](https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki#tr)
    1. Pay attention to the `TapTweak` in the spec: "the output key should commit to an unspendable script path instead of having no script path"
6. Using the RPC interface **of your own local, synced signet node**, scan all transactions in the first 300 blocks in the chain
    1. Look for your witness programs in all TX outputs - these are coins you received
    2. Look for your coins' outpoints in all TX inputs - these are coins you spent
7. Keep a running total of your wallet balance and return its name and final value

## Example output

```sh
# My wallet descriptor is
# tr(tprv8ZgxMBicQKsPePwbSC93GebdF8eNz2qkn7fxfGhNwJCyh2R6XKd7tyUs1wsyZSVfHYLL9g4aLy8LRrJhSUhkTHsAUY1WU2SDg2Sx6yS9TLj/86h/1h/0h/0/*)#uuj8klsl
$ python balance.py
wallet_000 9.19884135
```

## Submission

Each student will get a private fork of this repository when they accept the
GitHub Classroom assignment. You will commit and push your submissions to GitHub
which will evaluate the answers automatically. You can commit and push as often
as you like and GitHub will re-evaluate your code every time.

> [!TIP]
> Only push to your private fork's `main` branch. Do NOT open a pull request,
> autograder will ignore it.

Your code will be executed in an environment with a synced signet full node,
so any `bitcoin-cli -signet ...` commands executed in the shell should work
just like they do for you locally.

Your code must return exactly one line, a string, with your wallet name followed
by a single space and your wallet balance in tBTC with 8 decimal places
(see the [example](#example-output) above).

You are allowed to write your wallet code in any of the following programming
languages:

- Python
- C
- C++
- Rust

The autograder runs in Ubuntu 22 with
[these packages](https://github.com/actions/runner-images/blob/ubuntu22/20231217.2/images/ubuntu/Ubuntu2204-Readme.md)
installed by GitHub.

The autograder will run the bash script [solution/run_balance.sh](solution/run_balance.sh) which
MAY BE EDITED BY STUDENTS if you need to install additional dependencies. Only
the very last line of that script's output will be evaluated so make sure your
code runs last in the script, and prints the answer last!

The default language for this exercise is Python. The easiest way to complete
this project is to complete the obfuscated code template in
[solution/python/balance.py](solution/python/balance.py). No other files need
to be modified unless you want to start from scratch in Python or write in one
of the other languages.

There is also a Rust template in [solution/rust/](solution/rust/).
If you choose to work in Rust you will need to modify [solution/run_balance.sh](solution/run_balance.sh)
to execute the Rust code instead of Python.

Both Python and Rust examples import bindings to [libsecp256k1](https://github.com/bitcoin-core/secp256k1/)
which is the cryptography library used by Bitcoin Core. You **MAY** use
this library to access constants like `G` or the order of the curve,
but you **MAY NOT** use this or any other library to avoid implementing BIP32 yourself.

Familiarize yourself with the API for those bindings. The Python module in particular
is a bit older but both bindings support BIP340 just fine:
- Python: https://pypi.org/project/secp256k1/
- Rust: https://docs.rs/secp256k1/

> [!TIP]
> If you choose to write code in something other than Python you MUST modify
> [solution/run_balance.sh](solution/run_balance.sh) as well so that your code is compiled and
> executed appropriately!

## Hints

- [BIP 32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP 340: Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP 341: Taproot: SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP 386: tr() Output Script Descriptors](https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki)
- Be careful with floating-point precision! You may want to convert to integers (satoshis)
    - If you are using Python you may want to specify `json.loads(...,  parse_float=Decimal)`
- Familiarize yourself with the Bitcoin Core RPC interface
    - example: `bitcoin-cli -signet help getblock`
