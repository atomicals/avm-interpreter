# AVMN UniValue

## Summary

A universal value class, with JSON encoding and decoding.
UniValue is an abstract data type that may be a null, boolean, string,
number, array container, or a key/value dictionary container, nested to
an arbitrary depth.
This class is aligned with the JSON standard, [RFC
8259](https://tools.ietf.org/html/rfc8259).

UniValue was originally created by [Jeff Garzik](https://github.com/jgarzik/univalue/)
and is used in node software for many bitcoin-based cryptocurrencies.
**AVMN UniValue** is a fork of UniValue designed and maintained for use in [AVM Interpretor (AVMN)](https://atomicals.xyz/).
Unlike the [Bitcoin Core fork](https://github.com/bitcoin-core/univalue/),
AVMN UniValue contains large changes that improve *code quality* and *performance*.
The AVMN UniValue API deviates from the original UniValue API where necessary.

Development of AVMN UniValue is fully integrated with development of AVM Interpretor.
The AVMN UniValue library and call sites can be changed simultaneously, allowing rapid iterations.

## License

Like AVMN, AVMN UniValue is released under the terms of the MIT license. See
[COPYING](COPYING) for more information or see
<https://opensource.org/licenses/MIT>.

## Build instructions

### AVM Interpretor build

AVMN UniValue is fully integrated in the AVM Interpretor build system.
The library is built automatically while building the node.

Command to build and run tests in the AVMN build system:

```
ninja check-univalue
```

### Stand-alone build

UniValue is a standard GNU
[autotools](https://www.gnu.org/software/automake/manual/html_node/Autotools-Introduction.html)
project. Build and install instructions are available in the `INSTALL`
file provided with GNU autotools.

Commands to build the library stand-alone:

```
./autogen.sh
./configure
make
```

AVMN UniValue requires C++17 or later.
