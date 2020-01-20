"""
Copyright (c) 2019, The Decred developers
"""
import hashlib
import sys

from tinydecred.pydecred import txscript, nets
# Import the rest
from tinydecred.util.encode import ByteArray
from tinydecred.crypto import crypto, opcode
from tinydecred.pydecred.dcrdata import DcrdataClient
from tinydecred.pydecred.wire import msgtx

# --mainnet flag must be specified to use mainnet.
isMainNet = "--mainnet" in sys.argv
net = nets.mainnet if isMainNet else nets.testnet
if not isMainNet:
    print("Currently using testnet. To use mainnet, run the script with the --mainnet flag")

# We'll use this function a few times.
push = txscript.addData

# A hashing function.
hash256 = lambda b: ByteArray(hashlib.sha256(bytes(b)).digest())

# Standard network fee rate.
feeRate = 10 # DCR / byte

# Make sure we can connect to dcrdata before proceeding.
url = "https://{}.dcrdata.org".format("explorer" if isMainNet else "testnet")
dcrdata = DcrdataClient(url)
# Well be using the dcrdata Insight API
api = dcrdata.insight.api

# Collect the challenge address.
challengeAddr = input("What is the challenge address?\n")

# Make sure that there is an unspent output going to this address. We'll use the
# insight API exposed by dcrdata to find unspent outputs.

outputs = api.addr.utxo(challengeAddr)
if not outputs:
    raise AssertionError("No open challenge for " + challengeAddr)
utxo = outputs[0]
print("\nChallenge found at {}:{}".format(utxo["txid"], utxo["vout"]))
# The transaction hash is the byte-reversed decoding of the transaction ID.
txHash = reversed(ByteArray(utxo["txid"]))
vout = int(utxo["vout"])
reward = utxo["satoshis"]

# Collect an address to send the funds to.

recipient = input("\nEnter a {} address to receive the reward.\n".format(net.Name))
while True:
    try:
        rewardAddr = txscript.decodeAddress(recipient, net)
        break
    except:
        recipient = input("Invalid address. Enter an address for {}.\n".format(net.Name))

# Reject identical challenge and reward addresses as user error.
if challengeAddr == recipient:
    raise AssertionError("challenge address cannot be the same as reward address")

# If not on mainnet, the network will need to be specified correctly at the
# command line, or else decodeAddress will fail.
p2shAddr = txscript.decodeAddress(challengeAddr, net)

# Just a quick check that it's a P2SH address.
if not isinstance(p2shAddr, crypto.AddressScriptHash):
    raise AssertionError("challenge address is not a valid pay-to-script-hash address")

while True:
    answer = input("\nWhat is your answer?\n").strip()
    # Get the double hash, build the redeem script, and check if it hashes
    # correctly.
    answerHash = hash256(answer.encode("utf-8"))
    hash2x = hash256(answerHash)
    # Prepare the script and compare its hash to the hash encoded in the
    # challenge address.
    script = ByteArray(opcode.OP_SHA256) + push(hash2x) +  opcode.OP_EQUAL
    if crypto.hash160(bytes(script)) != p2shAddr.scriptHash:
        print("'{}' is the wrong answer.".format(answer))
        continue

    print("\nCorrect answer!")

    # Build the transaction.
    rewardTx = msgtx.MsgTx.new()
    # The input spends the challenge output. The signature script consists of
    # the answer hash and the redeem script.
    prevOut = msgtx.OutPoint(txHash, vout, msgtx.TxTreeRegular)
    sigScript = push(answerHash) + push(script)
    rewardTx.addTxIn(msgtx.TxIn(prevOut, signatureScript=sigScript))

    # Add the reward output with zero value for now.
    txout = msgtx.TxOut(pkScript=txscript.payToAddrScript(rewardAddr))
    rewardTx.addTxOut(txout)

    # Get the serialized size of the transaction. Since there are no signatures
    # involved, the size is known exactly. Use the size to calculate transaction
    # fees.
    size = rewardTx.serializeSize()
    fees = feeRate * size
    if reward <= fees:
        raise AssertionError(f"reward must be > fees")
    netReward = reward - fees
    # Set the value on the reward output.
    txout.value = netReward

    # Send the transaction, again using the dcrdata Insight API.
    api.tx.send.post({"rawtx": rewardTx.txHex()})
    print(round(netReward/1e8, 8), "\nDCR reward claimed. Transaction ID:", rewardTx.id())
    break
