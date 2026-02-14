#!/usr/bin/env python3

from decimal import Decimal
from subprocess import run
import json
from pathlib import Path

BTC = Decimal("0.00000000")
DESCRIPTOR_FILE = Path(__file__).resolve().parent.parent.parent / "datadir" / "student_wallet.json"
PAYMENTS_FILE = Path(__file__).resolve().parent.parent.parent / "payments.json"

def bcli(cmd: str):
    res = run(
            ["bitcoin-cli", "-regtest", "-rpcuser=student", "-rpcpassword=boss2026"] + cmd.split(" "),
            capture_output=True,
            encoding="utf-8")
    if res.returncode == 0:
        return res.stdout.strip()
    else:
        raise Exception(res.stderr.strip())


# Initialize wallet
bcli("createwallet student false true")
with open(DESCRIPTOR_FILE) as f:
    bcli(f"importdescriptors {f.read().replace(' ','')}")


# Load payments
with open(PAYMENTS_FILE) as f:
    payments = json.loads(f.read())

# Make payments
for payment in payments:
    # Get all UTXO in wallet coin pool
    coins = json.loads(bcli("listunspent"), parse_float=Decimal)

    # Select coins



    # Create transaction
    inputs = []
    outputs = []
    unsigned_tx = bcli(f"createrawtransaction {json.dumps(inputs).replace(' ','')} {json.dumps(outputs).replace(' ','')}")
    # Sign transaction
    signed_tx = json.loads(bcli(f"signrawtransactionwithwallet {unsigned_tx}"))["hex"]
    # Broadcast transaction without maxfeerate protection
    bcli(f"sendrawtransaction {signed_tx} 0")
    # Confirm transaciton
    bcli("generatetoaddress 1 bcrt1pqqqqrldkrl")
