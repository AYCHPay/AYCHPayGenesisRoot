Ubuntu & Debian Build Notes
====================
Some notes on how to build Genesis in Ubuntu & Debian.

For Unix systems other than Ubuntu & Debian, please see see [build-unix.md](build-unix.md))

Note
---------------------
Always use absolute paths to configure and compile Genesis Official and the dependencies,
for example, when specifying the path of the dependency:

	../dist/configure --enable-cxx --disable-shared --with-pic --prefix=$BDB_PREFIX

Here BDB_PREFIX must be an absolute path - it is defined using $(pwd) which ensures
the usage of the absolute path.

Dependencies
---------------------

These dependencies are required:

 Library     | Purpose          | Description
 ------------|------------------|----------------------
 libssl      | Crypto           | Random Number Generation, Elliptic Curve Cryptography
 libboost    | Utility          | Library for threading, data structures, etc
 libevent    | Networking       | OS independent asynchronous networking
 libb2       | Crypto           | Crypto Library, lighter than libsodium

Optional dependencies:

 Library     | Purpose          | Description
 ------------|------------------|----------------------
 miniupnpc   | UPnP Support     | Firewall-jumping support
 libdb4.8    | Berkeley DB      | Wallet storage (only needed when wallet enabled)
 qt          | GUI              | GUI toolkit (only needed when GUI enabled)
 protobuf    | Payments in GUI  | Data interchange format used for payment protocol (only needed when GUI enabled)
 libqrencode | QR codes in GUI  | Optional for generating QR codes (only needed when GUI enabled)
 univalue    | Utility          | JSON parsing and encoding (bundled version will be used unless --with-system-univalue passed to configure)
 libzmq3     | ZMQ notification | Optional, allows generating ZMQ notifications (requires ZMQ version >= 4.x)

For the versions used, see [dependencies.md](dependencies.md)

Memory Requirements
--------------------

C++ compilers are memory-hungry. It is recommended to have at least 1.5 GB of
memory available when compiling Genesis. On systems with less, gcc can be
tuned to conserve memory with additional CXXFLAGS:

    ./configure CXXFLAGS="--param ggc-min-expand=1 --param ggc-min-heapsize=32768"

Dependency Build Instructions:
----------------------------------------------

Build requirements:

    sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils python3 libb2-dev git curl
    sudo apt-get install libboost-all-dev

BerkeleyDB is required for the wallet.

    sudo apt-get install software-properties-common
    sudo add-apt-repository ppa:bitcoin/bitcoin
    sudo apt-get update
    sudo apt-get install libdb4.8-dev libdb4.8++-dev

Ubuntu and Debian have their own libdb-dev and libdb++-dev packages, but these will install
BerkeleyDB 5.1 or later, which break binary wallet compatibility with the distributed executables which
are based on BerkeleyDB 4.8. If you do not care about wallet compatibility,
pass `--with-incompatible-bdb` to configure.

See the section "Disable-wallet mode" to build Genesis without wallet.

Optional: See --with-miniupnpc and --enable-upnp-default

    sudo apt-get install libminiupnpc-dev

Optional: ZMQ dependencies (provides ZMQ API 4.x)

    sudo apt-get install libzmq3-dev

Building Genesis Official (w/out QT)
--------------------
  
```
$ git clone https://github.com/genesisofficial/genesis.git
$ cd genesis/depends
$ make
$ cd ..
$ ./autogen.sh
$ ./configure
$ make
```

Building Genesis Official (w/ QT)
--------------------

Install remaining dependencies

    sudo apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler
    
Optional: libqrencode

    sudo apt-get install libqrencode-dev
    
Now build
```
$ git clone https://github.com/genesisofficial/genesis.git
$ cd genesis/depends
$ make
$ cd ..
$ ./autogen.sh
$ ./configure --prefix=`pwd`/depends/x86_64-pc-linux-gnu
$ make
$ make install
```

The command `make install` installs the executables in the `./depends/x86_64-pc-linux-gnu/bin/` directory. Make sure you define absolute path.

Notes
-----
The release is built with GCC and then "strip genesisd" to strip the debug
symbols, which reduces the executable size by about 90%.

Ubuntu 16.04 may encounter the following error. Here's how to remedy:

    configure: error: Wrong libsodium: version >= 1.0.13 required

```
$ wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.16.tar.gz
$ tar -xzf libsodium-1.0.16.tar.gz
$ cd libsodium-1.0.16
$ ./configure
$ make
$ make install
```

Also on Ubuntu 16.04, running the daemon might cause a "Core Aborted" error. Here's the work around

```
wget http://de.archive.ubuntu.com/ubuntu/pool/universe/libs/libsodium/libsodium-dev_1.0.13-1_amd64.deb
wget http://de.archive.ubuntu.com/ubuntu/pool/universe/libs/libsodium/libsodium18_1.0.13-1_amd64.deb
sudo dpkg -i libsodium*deb
```
Then perform the build again. (configure, make)

In case of errors asking to ```recompile with fPIC``` add ```--with-pic``` to your ./configure command and make again

miniupnpc
---------

[miniupnpc](http://miniupnp.free.fr/) may be used for UPnP port mapping.  It can be downloaded from [here](
http://miniupnp.tuxfamily.org/files/).  UPnP support is compiled in and
turned off by default.  See the configure options for upnp behavior desired:

	--without-miniupnpc      No UPnP support miniupnp not required
	--disable-upnp-default   (the default) UPnP support turned off by default at runtime
	--enable-upnp-default    UPnP support turned on by default at runtime


Berkeley DB
-----------
It is recommended to use Berkeley DB 4.8. If you have to build it yourself,
you can use [the installation script included in contrib/](/contrib/install_db4.sh)
like so

```shell
./contrib/install_db4.sh `pwd`
```

from the root of the repository.

**Note**: You only need Berkeley DB if the wallet is enabled (see the section *Disable-Wallet mode* below).

Boost
-----
If you need to build Boost yourself:

	sudo su
	./bootstrap.sh
	./bjam install


Security
--------
To help make your Genesis Official installation more secure by making certain attacks impossible to
exploit even if a vulnerability is found, binaries are hardened by default.
This can be disabled with:

Hardening Flags:

	./configure --enable-hardening
	./configure --disable-hardening


Hardening enables the following features:

* Position Independent Executable
    Build position independent code to take advantage of Address Space Layout Randomization
    offered by some kernels. Attackers who can cause execution of code at an arbitrary memory
    location are thwarted if they don't know where anything useful is located.
    The stack and heap are randomly located by default but this allows the code section to be
    randomly located as well.

    On an AMD64 processor where a library was not compiled with -fPIC, this will cause an error
    such as: "relocation R_X86_64_32 against `......' can not be used when making a shared object;"

    To test that you have built PIE executable, install scanelf, part of paxutils, and use:

    	scanelf -e ./genesis

    The output should contain:

     TYPE
    ET_DYN

* Non-executable Stack
    If the stack is executable then trivial stack-based buffer overflow exploits are possible if
    vulnerable buffers are found. By default, Genesis Official should be built with a non-executable stack
    but if one of the libraries it uses asks for an executable stack or someone makes a mistake
    and uses a compiler extension which requires an executable stack, it will silently build an
    executable without the non-executable stack protection.

    To verify that the stack is non-executable after compiling use:
    `scanelf -e ./genesis`

    The output should contain:
	STK/REL/PTL
	RW- R-- RW-

    The STK RW- means that the stack is readable and writeable but not executable.

Disable-wallet mode
--------------------
When the intention is to run only a P2P node without a wallet, Genesis Official may be compiled in
disable-wallet mode with:

    ./configure --disable-wallet

In this case there is no dependency on Berkeley DB 4.8.

Mining is also possible in disable-wallet mode, but only using the `getblocktemplate` RPC
call not `getwork`.

Additional Configure Flags
--------------------------
A list of additional configure flags can be displayed with:

    ./configure --help

For further documentation on the depends system see [README.md](../depends/README.md) in the depends directory.
