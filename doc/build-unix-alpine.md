# Alpine build guide

Instructions for alpine 3.13

## Preparation

Minimal dependencies:

```sh
    apk add git boost-dev cmake libevent-dev openssl-dev build-base py-pip db-dev help2man bash
    pip install ninja
```

NOTE: Since alpine 3.12, `ninja` was replaced with `samurai`, which is not fully compatible with
the build system, hence the need for installing it with `pip`
 
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
