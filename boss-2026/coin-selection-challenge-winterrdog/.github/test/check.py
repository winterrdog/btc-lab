#!/usr/bin/env python3

import atexit
from decimal import Decimal
from subprocess import run, Popen
import json
from pathlib import Path
from time import sleep

BTC = Decimal("0.00000000")
DATA_DIR = Path(__file__).resolve().parent.parent.parent / "datadir" / "node0"
DESCRIPTOR_FILE = Path(__file__).resolve().parent.parent.parent / "datadir" / "student_wallet.json"
PAYMENTS_FILE = Path(__file__).resolve().parent.parent.parent / "payments.json"
ARTIFACT = Path(__file__).resolve().parent.parent / "getbalances.json"

def bcli(cmd: str):
    res = run(
            ["bitcoin-cli", "-regtest", "-rpcuser=admin", "-rpcpassword=boss2026"] + cmd.split(" "),
            capture_output=True,
            encoding="utf-8")
    if res.returncode == 0:
        return res.stdout.strip()
    else:
        raise Exception(res.stderr.strip())

run(["killall", "-9", "bitcoind"])
node = Popen(["bitcoind", f"-datadir={DATA_DIR}", "-rpcuser=admin", "-rpcpassword=boss2026", "-rpcwhitelistdefault=0", "-txindex"])

# Prepare node shutdown in advance
def cleanup():
    try:
        bcli("stop")
    except Exception as e:
        print(f"Error stopping: {e}, killing...")
        node.kill()
    node.wait()
atexit.register(cleanup)

# Wait for ready
while True:
    try:
        count = int(bcli("getblockcount"))
        if count >= 110:
            break
        else:
            sleep(1)
    except Exception as e:
        print(e)
        sleep(1)

# Load payment requirements
with open(PAYMENTS_FILE) as f:
    payments = json.loads(f.read())
payments.reverse()

# Load wallet
bcli("loadwallet student")

count = 111
while True:
    try:
        blockhash = bcli(f"getblockhash {count}")
    except Exception as e:
        if "Block height out of range" in str(e):
            print("We ran out of blocks!")
            assert len(payments) == 0, "Not all payments were executed"
            print("All payments were executed correctly ✅")
            break
    print(f"Height: {count} hash: {blockhash}")
    block = json.loads(bcli(f"getblock {blockhash} 2"))
    assert len(block["tx"]) == 2, "Each block must have exactly one TX (plus coinbase)"
    assert block["tx"][0]["vout"][0]["scriptPubKey"]["address"] == "bcrt1pqqqqrldkrl", "Generated blocks must pay subsidy to specified burn address"

    expected = payments.pop()
    actual = block["tx"][1]
    actual_rate = (Decimal(actual["fee"]) / Decimal(actual["vsize"]) * Decimal(1000)).quantize(BTC)
    actual["rate"] = str(actual_rate)

    found = False
    for out in actual["vout"]:
        if Decimal(str(out["value"])) == Decimal(expected["amount"]) and out["scriptPubKey"]["address"] == expected["address"]:
            found = True
            break
    assert found, f"Could not find expected payment in transaction output:\nexpected: {expected}\nacutal: {json.dumps(actual, indent=2)}"

    assert Decimal(expected["rate"]) <= actual_rate, f"Insufficient fee rate:\nexpected: {expected}\nacutal: {json.dumps(actual, indent=2)}"

    count += 1

getbalances = bcli("getbalances")
print(getbalances)
with open(ARTIFACT, "w") as f:
    f.write(getbalances)
