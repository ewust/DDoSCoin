# DDoSCoin

DDoSCoin is a conceptual cryptocurrency with an "evil" proof-of-work. Rather
than use a hash-based proof-of-work like Bitcoin, DDoSCoin allows miners to
prove that they have contributed to a Distributed Denial of Service (DDoS)
against a specific target.

## How it works

DDoSCoin incentivizes miners to make large numbers of requests to specific
target TLSv1.2 servers. Occasionally, the response from a target webserver
will satisify specific criteria, and the miner can publish the network packet
trace as a proof-of-work, creating the next block in the DDoSCoin blockchain,
and collecting the miner's block reward.

To do this, miners take the hash of the latest block, the merkle root of
transactions to be included in the next block (including a coinbase
transaction to the miner), and a random fixed-length nonce, and hash these to
get the value the miner will use as the client random in its Client Hello
message to the TLS server. The server will respond with a Server Hello,
Certificate, and Server Key Exchange.

Inside the Server Key Exchange in TLS1.2, the server sends its contribution to
the key agreement protocol, and signs the parameters with its private key. The
key exchange parameters are signed along with the client and server randoms,
which allows the miner to prove to anyone that the server has seen the
particular client random (i.e. the client actually contacted the server with
that client random).

If a hash over the Server Key Exchange and the random nonce used in the client
random results in a value less than the current target, the miner can publish
this transaction to create the next block.

In the block, the miner must publish the transactions, the fixed-length nonce,
the server random, the server key exchange parameters, the key exchange
signature, and the TLS certificate of the target. To verify blocks, other
miners recreate the client random by hashing the hash of the previous block,
transaction merkle root, and nonce. The server's key exchange signature over
this client random, provided server random, and provided server key exchange
parameters is verified using the certificate public key. The fingerprint of
the certificate is verfied to belong to a valid specified target. The
difficulty is verified by hashing the server key exchange message and the
nonce, and verifying it is less than the current difficulty. If all of these
checks pass (plus any standard transaction validity checks pass), then this
block is considered valid.

## Technical details

```
nonce = 32-byte random value
client_random = SHA256(SHA256(prev_block) || tx_merkle_root || nonce)

// Server Key Exchange message:
//      server_key_exchange_params
//      signature
// where signature = Sign(client_random || server_random ||
//                        server_key_exchange_params)

difficulty = SHA256(server_key_exchange_params || signature || nonce)
if difficulty < target:
    // This is a new block!
else:
    // Make more connections to the target >:)
```

The nonce is included in the difficulty hash because otherwise the server
could prevent anyone from ever getting a valid block (thus disincentivizing
miners from attacking it) by discarding key exchange parameters whos hash
would be less than the target difficulty. By blinding this from the server
(while also forcing the client to commit to it in the client random), the
server cannot tell if a response will be useful to a potential DDoSCoin miner.


