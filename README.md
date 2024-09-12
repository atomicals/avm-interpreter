# Atomicals Virtual Machine Interpreter

The Atomicals Virtual Machine (AVM) Interpreter is a modified version of the Bitcoin interpreter with a few notable differences:

- Majority of original OP codes are reenabled (`OP_CAT, OP_MUL, OP_DIV, OP_LSHIFT`, ...)
- Big number support added for arbitrarily large numbers
- New OP codes for handling deposit and withdraw of NFT and ARC20 tokens
- New OP codes for reading and writing to private state storage
- New OP code `OP_HASH_FN` provides hashing capabilities with additional digest algorithms
- Custom signature algorithm to authorize contract calls: `OP_CHECKAUTHSIG(VERIFY)`
    - Removal of `OP_CHECKSIG(VERIFY)`

# How it works

Read the [AVM White Paper](https://github.com/atomicals/avm-whitepaper) for an architectural overview of the system.

The AVM interpreter is a sandbox which is invoked on a per-contract basis to simulate the execution of a Bitcoin script program. 
The library method `atomicalsconsensus_verify_script_avm` is exposed to allow calling from external programs, the caller provides
the state inputs, scripts and other variables such as current block information. Upon successful execution that updated state variables are returned as CBOR encoded datastructures to simplify the passing of information back to the caller.

# Compile and Install

See the [Build Docs](doc) for instructions on how to compile and install on your platform.

Once you have successfully compiled and installed it on your system, note the path that the output of the `sudo ninja install`.
You will see output such as:

```
sudo ninja install

...

[36/37] Install the project...
-- Install configuration: "RelWithDebInfo"
-- Installing: /usr/local/lib/libatomicalsconsensus.so.1.0.0
-- Up-to-date: /usr/local/lib/libatomicalsconsensus.so.1
-- Up-to-date: /usr/local/lib/libatomicalsconsensus.so
-- Installing: /usr/local/include/atomicalsconsensus.h
-- Installing: /usr/local/bin/avm-cli
-- Up-to-date: /usr/local/lib/libsecp256k1.a
-- Up-to-date: /usr/local/include/secp256k1.h
-- Up-to-date: /usr/local/include/secp256k1_preallocated.h
-- Up-to-date: /usr/local/include/secp256k1_recovery.h
-- Up-to-date: /usr/local/include/secp256k1_schnorr.h

```

The library we need to point the ElectrumX instance to is `/usr/local/lib/libatomicalsconsensus.so.1` and you will update the environment configuration file for the [atomicals-electrumx](https://github.com/atomicals/atomicals-electrumx/tree/avmbeta) indexer:

config.env (electrumx server):

```
ATOMICALSCONSENSUS_LIB_PATH=/usr/local/lib/libatomicalsconsensus.so.1
```