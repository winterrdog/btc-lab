# Signet Wallet Project -- Challenge #2: SPEND

The goal of this project is to write a simple wallet and use it
to interact with a custom signet network provided by the administrator.

There are two challenges to complete (more details below):
1. Given the private descriptor for a wallet and a blockchain full of transactions,
provide your wallet's current balance.
2. Create two valid transactions, spending from a 2-of-2 multi-sig output to an OP_RETURN.

## Simplify

To reduce the scope of this project the wallet will be very limited:
- No separate change addresses: one descriptor is used for all internal and external addressees.
- No [VarInt](https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer):
all vectors will be under 255 bytes in length and always require one single
byte to indicate length.
- All sending and receiving addresses will be Taproot ([`p2tr`](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki))
- Fees can be hard-coded by value, no fee estimation is necessary.
- Transactions you create will always have exactly 1 input and 2 outputs.
- Don't worry about invalid keys [(probabilty is less than 1 in 2<sup>127</sup>)](https://bitcoin.stackexchange.com/a/53182/3667)
- Other constants:
    - All transactions will be version 2 (little-endian encoded as `\x02\x00\x00\x00`)
    - All input sequences will be `0xffffffff`
    - All transaction locktimes will be `0x00000000`
    - All input scriptSigs will be `0x00` (because we are only concerned with [segregated witness inputs](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#witness-program))
    - All sighash flags will be `SIGHASH_DEFAULT` which is `0x00` in signatures and encoded as `\x00\x00\x00\x00` in [transaction commitments](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message)

## Custom Signet

We will generate a signet blockchain and host a mining node that everyone
can connect to, download the chain (around 20 MB), and broadcast their completed transactions.
We will have already generated private key descriptors for each student and used
them to generate hundreds of transactions sending and receiving in the chain.
Each student will be provided (by email) with a single
[`tr()` descriptor](https://github.com/bitcoin/bips/blob/master/bip-0386.mediawiki)
with an extended private key like this example:

`wallet_000: tr(tprv8ZgxMBicQKsPePwbSC93GebdF8eNz2qkn7fxfGhNwJCyh2R6XKd7tyUs1wsyZSVfHYLL9g4aLy8LRrJhSUhkTHsAUY1WU2SDg2Sx6yS9TLj/86h/1h/0h/0/*)#uuj8klsl`

The important elements here are the extended private key (`tprv...`) and the
derivation path (`86h/1h/0h/0/*`).

> [!TIP]
> If you have already connected to the "default" (or any other) signet network
> with your node, you may need to rename / move your existing data directory. See
> [#27494](https://github.com/bitcoin/bitcoin/issues/27494)

A `bitcoin.conf` file will be provided to students in [config/bitcoin.conf](config/bitcoin.conf)
which will set the address of the mining node as well as provide the signet
[challenge](https://en.bitcoin.it/wiki/Signet). Copy this file to your system's
[default datadir location](https://github.com/bitcoin/bitcoin/blob/master/doc/bitcoin-conf.md#configuration-file-path)
and start Bitcoin Core:

`bitcoind -signet`

You should also then be able to
execute RPCs with (for example):

`bitcoin-cli -signet getblockcount`

# Challenge 2 (transactions, scripts, and signatures)

See [Send Multisig](./send_multisig.md) coding challenge
