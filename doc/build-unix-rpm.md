# Fedora / CentOS build guide

(updated for Fedora 31)

## Preparation

Minimal build requirements:

```bash
sudo dnf install boost-devel cmake gcc-c++ git libevent-devel  ninja-build openssl-devel python3 help2man
```
 

## Building

Once you have installed the required dependencies (see sections above), you can
build AVM as such:

First fetch the code (if you haven't done so already).

```sh
git clone https://github.com/atomicals/avm.git
```

Change to the avm directory, make `build` dir, and change to that directory

```sh
cd avm/
mkdir build
cd build
```
 
**Choose one:**

 
```sh
# Build avm-cli and libatomicalsconsensus
cmake -GNinja ..
```

Next, finish the build

```sh
ninja
```

You will find  `avm-cli` 
binaries in `/build/src`.
 
```sh
sudo ninja install #optional
```