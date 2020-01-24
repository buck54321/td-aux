"""
Copyright (c) 2019, The Decred developers
"""
import hashlib
import sys

from decred.util.encode import ByteArray
from decred.crypto import opcode, crypto
from decred.dcr import nets, txscript

# --mainnet flag must be specified to use mainnet.
isMainNet = "--mainnet" in sys.argv
net = nets.mainnet if isMainNet else nets.testnet
if not isMainNet:
	print("Currently using testnet. To use mainnet, run the script with the --mainnet flag\n")

# A hashing function.
hash256 = lambda b: ByteArray(hashlib.sha256(bytes(b)).digest())

# Get the answer from stdin. Strip whitespace from the ends, but nothing else,
# i.e. input is not converted to lower-case.
answer = input("What is the answer?\n").strip().encode("utf-8")

# The actual input needed to spend the transaction is the hash of the answer.
answerHash = hash256(answer)
# The input will be checked against its hash (the double-hash of the answer) to
# satisfy the script.
doubleHash = hash256(answerHash)

# Build the script. The first opcode says to hash the input in-place on the
# stack.
redeemScript = ByteArray(opcode.OP_SHA256)
# Add the doubleHash to the stack.
redeemScript += txscript.addData(doubleHash)
# The last opcode compares the two items on the stack, leaving a 1 on the stack
# if they are equal.
redeemScript += opcode.OP_EQUAL

# Create the address.
p2shAddr = crypto.newAddressScriptHash(redeemScript, net)

# Print the address.
print("Fund this challenge by sending Decred to", p2shAddr.string())
