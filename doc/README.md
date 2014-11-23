Kryptohash 0.3.0 BETA
=====================

Copyright (c) 2014 Kryptohash Developers
Copyright (c) 2009-2014 Bitcoin Developers


Setup
---------------------
[Kryptohash Core](http://www.kryptohash.org) is the original Kryptohash client and it builds the backbone of the network. However, it downloads and stores the entire history of Kryptohash coin transactions; depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more. Thankfully you only have to do this once.

Running
---------------------
The following are some helpful notes on how to run Kryptohash on your native platform. 

### Unix

You need the Qt4 run-time libraries to run Bitcoin-Qt. On Debian or Ubuntu:

	sudo apt-get install libqtgui4

Unpack the files into a directory and run:

- bin/32/kryptohash-qt (GUI, 32-bit) or bin/32/kryptohashd (headless, 32-bit)
- bin/64/kryptohash-qt (GUI, 64-bit) or bin/64/kryptohashd (headless, 64-bit)



### Windows

Unpack the files into a directory, and then run kryptohash-qt.exe.

### OSX  (Not yet available)

Drag Kryptohash-Qt to your applications folder, and then run Kryptohash-Qt.

### Need Help?

* See the documentation at the the Wiki section (http://www.kryptohash.org)
* Ask for help on the [BitcoinTalk] (https://bitcointalk.org/) forums.

Building
---------
The source code can be found at GitHub (www.github.com/kryptohash)

The following are developer notes on how to build Kryptohash on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [OSX Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-msw.md)


### Resources
* Discuss on the [BitcoinTalk](https://bitcointalk.org/) forums.

### Miscellaneous
- [Tor Support](tor.md)

License
---------------------
Distributed under the [MIT/X11 software license](http://www.opensource.org/licenses/mit-license.php).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](http://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
