# Ubuntu & Debian build guide

Updated for Ubuntu 19.04 and Debian Buster (10). If you run an older version,
please see [section below](build-unix-deb.md#getting-a-newer-cmake-on-older-os),
about obtaining the required version of `cmake`.

## Preparation

Minimal build requirements

```bash
    sudo apt-get install build-essential cmake git libboost-chrono-dev libboost-filesystem-dev libboost-test-dev libboost-thread-dev libevent-dev   libssl-dev help2man ninja-build python3
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

## Getting a newer cmake on older OS

On versions prior to Ubuntu 19.04 and Debian 10, the `cmake` package is too old
and needs to be installed from the Kitware APT repository:

```bash
    sudo apt-get install apt-transport-https ca-certificates gnupg software-properties-common wget
    wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | sudo apt-key add -
```

Add the repository corresponding to your version (see [instructions from Kitware](https://apt.kitware.com)).
For Ubuntu Bionic (18.04):

```bash
    sudo apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'
```

Then update the package list and install `cmake`:

```bash
    sudo apt update
    sudo apt install cmake
```

