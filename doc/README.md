# AVM Interpretor Setup

To download AVM Interpretor https://github.com/atomicals/avm-interpreter.git
 
## Running

The following are some helpful notes on how to run AVM Interpretor on your
native platform.

### Unix

Quick Start (Build from Source)

```bash
# Clone repository and build:
mkdir build && cd build
cmake -GNinja ..
```

Next, finish the build

```bash
ninja
```

Install:

```bash
ninja install
```

Connect installed AVM libraries to the ElectrumX indexer.
