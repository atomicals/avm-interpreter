# FreeBSD build guide

(updated for FreeBSD 12.1)

This guide describes how to build bitcoind and command-line utilities on FreeBSD.

This guide does not contain instructions for building the GUI.

## Preparation

You will need the following dependencies, which can be installed as root via pkg:

```bash
pkg install cmake libevent ninja openssl boost-libs git
```
 
## Building AVM Interpretor

Download the source code:

```bash
git clone https://github.com/avm/avm.git
cd avm/
```

To build with wallet:

```bash
mkdir build
cd build
cmake -GNinja -DBUILD_AVM_QT=OFF ..
ninja
ninja check # recommended
```

To build without wallet:

```bash
mkdir build
cd build
cmake -GNinja -DBUILD_AVM_QT=OFF -DBUILD_AVM_WALLET=OFF ..
ninja
ninja check # recommended
```

To build with wallet and GUI:

```bash
mkdir build
cd build
cmake -GNinja ..
ninja
ninja check # recommended
ninja test_bitcoin-qt # recommended
```

After a successful test you can install the newly built binaries to your bin directory.
Note that this will probably overwrite any previous version installed, including
binaries from different sources.
It might be necessary to run as root, depending on your system configuration:

```bash
ninja install #optional
```
