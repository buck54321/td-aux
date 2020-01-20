"""
Copyright (c) 2019, The Decred developers
"""
import hashlib

from tinydecred.util.encode import ByteArray
from tinydecred.crypto import opcode, crypto
from tinydecred.pydecred.txscript import addData
from tinydecred import config

# Load the tinydecred configuration since we'll need to know what network was
# specified at the command line.
cfg = config.load()

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
redeemScript += addData(doubleHash)
# The last opcode compares the two items on the stack, leaving a 1 on the stack
# if they are equal.
redeemScript += opcode.OP_EQUAL

# Create the address.
p2shAddr = crypto.newAddressScriptHash(redeemScript, cfg.net)

# Print the address.
print("Fund this challenge by sending Decred to", p2shAddr.string())
