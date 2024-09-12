# Arch Linux build guide

## Preparation

You will need the following dependencies:

```bash
    pacman -S boost cmake git libevent ninja python help2man
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
