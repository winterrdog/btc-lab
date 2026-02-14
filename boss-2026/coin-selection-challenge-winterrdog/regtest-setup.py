#!/usr/bin/env python3

from decimal import Decimal
from random import choice, randrange
from pathlib import Path
from subprocess import run
import os
import json
import sys

BTC = Decimal("0.00000000")

# Blocks with miner->student payments
FUNDING_BLOCKS = 10
# Max outputs in each miner->student tx (1 per block)
MAX_FUNDS_PER_BLOCK = 1000
# Smallest payment output miner->student in satoshis
MIN_WALLET_COIN = 1
MAX_WALLET_COIN = 100000000

# Total number of required payments
NUM_PAYMENTS = 500
# How many times the feerate goes from to low to high to low
FEE_RATE_WAVES = 3
# Fee rate range
MIN_FEE = Decimal("0.00001000")
MAX_FEE = Decimal("0.00300000")
# Payment range
MIN_PAYMENT = Decimal("0.00001000")
MAX_PAYMENT = Decimal("3.0")

# Destination for bitcoin datadir
DATA_DIR = Path(__file__).resolve().parent / "datadir"

# Import Bitcoin Core test framework as a library
if len(sys.argv) != 2:
    raise Exception("Args: <path to bitcoin core repo>")

repo = Path(sys.argv.pop())
if not repo.exists():
    raise Exception(f"{repo} does not exist")
sys.path.insert(0, f"{repo / 'build' / 'test' / 'functional'}")
from test_framework.test_shell import TestShell  # noqa: E402

# Setup regtest test shell
shell = TestShell().setup(num_nodes=1, setup_clean_chain=True, tmpdir=DATA_DIR, extra_args=[["-dustrelayfee=0"]])
shell.options.nocleanup = True
node = shell.nodes[0]

# Miner
node.createwallet(wallet_name="miner")
miner = node.get_wallet_rpc("miner")
miner_addr = miner.getnewaddress(address_type="bech32m")

# Student wallet
node.createwallet(wallet_name="student")
student = node.get_wallet_rpc("student")

# Generate the chain
def generate(n):
    shell.log.info(shell.generatetoaddress(node, n, address=miner_addr, sync_fun=shell.no_op()))

generate(100)

# Miner funds student whenever it can
def maybe_fund_wallet():
    try:
        bal = miner.getbalances()
        trusted = bal["mine"]["trusted"]
        immature = bal["mine"]["immature"]
        shell.log.info(f"Miner wallet balance: trusted={trusted} immature={immature}")
        if trusted < 1:
            # Probably need to wait for another new block
            return
    except Exception as e:
        shell.log.info(f"Failed to get miner wallet balance: {e}")
        return
    # Fund wallet
    try:
        outputs = {}
        # save for fee
        trusted -= Decimal(0.0002)
        for _ in range(MAX_FUNDS_PER_BLOCK):
            if trusted < Decimal(0.00002):
                break
            addr = student.getnewaddress(address_type=choice(["legacy", "p2sh-segwit", "bech32", "bech32m"]))
            amt = randrange(MIN_WALLET_COIN, MAX_WALLET_COIN) / 1e8
            trusted -= Decimal(amt)
            if trusted < 0:
                break
            outputs[addr] = amt
        tx = miner.sendmany("", outputs)
        shell.log.info(f"Sending tx from miner to student: {tx}")
    except Exception as e:
        shell.log.info(f"Failed to send tx from miner to student: {e}")

while True:
    if node.getblockcount() < 100 + FUNDING_BLOCKS:
        maybe_fund_wallet()
    else:
        break
    generate(1)

# Export private keys
desc = student.listdescriptors(private=True)["descriptors"]
with open(DATA_DIR / "student_wallet.json", "w") as f:
    f.write(json.dumps(desc))

# Generate payments list using the miner wallet for addresses
payments = []
payments_per_wave = int(NUM_PAYMENTS / FEE_RATE_WAVES)
fee_range = MAX_FEE - MIN_FEE
payment_range = MAX_PAYMENT - MIN_PAYMENT

student_balance = Decimal(student.getbalance())
print(f"Starting student wallet balance: {student_balance}")
for w in range(FEE_RATE_WAVES):
    for p in range(payments_per_wave):
        print(f"Wave {w} of {FEE_RATE_WAVES}, payment #{p} (total: {len(payments)})")
        wave_progress = p / payments_per_wave
        fee_rate = ((Decimal(wave_progress) * fee_range) + MIN_FEE).quantize(BTC)
        payment_progress = len(payments) / NUM_PAYMENTS
        max_payment = (Decimal(payment_progress) * MAX_PAYMENT) + MIN_PAYMENT
        min_sats = int(MIN_PAYMENT * Decimal(1e8))
        max_sats = int(max_payment * Decimal(1e8)) + 1
        amount_sats = randrange(min_sats, max_sats)
        amount = Decimal(amount_sats / 1e8).quantize(BTC)
        address = miner.getnewaddress(address_type=choice(["legacy", "p2sh-segwit", "bech32", "bech32m"]))
        options = {
            "address": address,
            "amount": str(amount),
            "rate": str(fee_rate)
        }
        payments.append(options)
        print(f" {options}")
        student_balance -= amount
        print(f" Student wallet balance left for fees: {student_balance}")

with open(DATA_DIR / ".." / "payments.json", "w") as f:
    f.write(json.dumps(payments, indent=2))

coinpool = [{"address": c["address"], "amount": c["amount"]} for c in student.listunspent()]
print(json.dumps(coinpool, default=str, indent=2))

print(json.dumps(student.listunspent(), indent=2, default=lambda o: str(o) if isinstance(o, Decimal) else o))

shell.shutdown()

# Replace conf file
conf = """
regtest=1
[regtest]
reindex=1
maxtxfee=21000000
mintxfee=0.00000001
dustrelayfee=0
# password is `boss2026`
rpcauth=student:9e2a740807c433cad4e1ceba17d5a4eb$fb01f6ab01ede71d28d6c7928e1d9ebd31637a3a83bec3ae798579a7f4997e15
rpcwhitelist=student:listunspent,getrawchangeaddress,createrawtransaction,signrawtransactionwithwallet,sendrawtransaction,getbalances,getblockcount,createwallet,importdescriptors,generatetoaddress
"""
os.unlink(DATA_DIR / "node0" / "bitcoin.conf")
with open(DATA_DIR / "node0" / "bitcoin.conf", "w") as f:
    f.write(conf)

# Clean up
run(['git', 'clean', '-xdf', DATA_DIR])
