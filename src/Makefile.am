include Makefile.include

AM_CPPFLAGS += -I$(builddir)

noinst_LIBRARIES = \
  libkryptohash_server.a \
  libkryptohash_common.a \
  libkryptohash_cli.a \
  libkeccak.a \
  libed25519.a

if ENABLE_WALLET
noinst_LIBRARIES += libkryptohash_wallet.a
endif

bin_PROGRAMS =

if BUILD_KRYPTOHASHD
  bin_PROGRAMS += kryptohashd
endif

if BUILD_KRYPTOHASH_CLI
  bin_PROGRAMS += kryptohash-cli
endif

SUBDIRS = . $(BUILD_QT)
DIST_SUBDIRS = . qt
.PHONY: FORCE
# kryptohash core #
KRYPTOHASH_CORE_H = \
  addrman.h \
  alert.h \
  allocators.h \
  base58.h bignum.h \
  bloom.h \
  chainparams.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coincontrol.h \
  coins.h \
  compat.h \
  core.h \
  crypter.h \
  db.h \
  genesis.h \
  hash.h \
  init.h \
  key.h \
  keystore.h \
  leveldbwrapper.h \
  limitedmap.h \
  main.h \
  miner.h \
  mruset.h \
  netbase.h \
  net.h \
  noui.h \
  protocol.h \
  rpcclient.h \
  rpcprotocol.h \
  rpcserver.h \
  script.h \
  serialize.h \
  sync.h \
  threadsafety.h \
  tinyformat.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  uint256.h \
  util.h \
  version.h \
  walletdb.h \
  wallet.h \
  kryptohashnet.h

JSON_H = \
  json/json_spirit.h \
  json/json_spirit_error_position.h \
  json/json_spirit_reader.h \
  json/json_spirit_reader_template.h \
  json/json_spirit_stream_reader.h \
  json/json_spirit_utils.h \
  json/json_spirit_value.h \
  json/json_spirit_writer.h \
  json/json_spirit_writer_template.h

KECCAK_H = \
  keccak/sha3.h \
  keccak/KeccakRnd.h \
  keccak/KeccakHash.h \
  keccak/KeccakSponge.h \
  keccak/brg_endian.h \
  keccak/SnP-interface.h \
  keccak/SnP/SnP.h \
  keccak/SnP/SnP-Relaned.h \
  keccak/SnP/SnP-FBWL-default.h \
  keccak/KeccakF-1600/KeccakF-1600-interface.h

ED25519_H = \
  ed25519/ed25519.h \
  ed25519/ge.h \
  ed25519/fe.h \
  ed25519/sc.h \
  ed25519/precomp_data.h \
  ed25519/fixedint.h
  
obj/build.h: FORCE
	@$(MKDIR_P) $(abs_top_builddir)/src/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
version.o: obj/build.h

libkryptohash_server_a_SOURCES = \
  addrman.cpp \
  alert.cpp \
  bloom.cpp \
  checkpoints.cpp \
  coins.cpp \
  init.cpp \
  keystore.cpp \
  leveldbwrapper.cpp \
  main.cpp \
  miner.cpp \
  net.cpp \
  noui.cpp \
  rpcblockchain.cpp \
  rpcmining.cpp \
  rpcmisc.cpp \
  rpcnet.cpp \
  rpcrawtransaction.cpp \
  rpcserver.cpp \
  txdb.cpp \
  txmempool.cpp \
  $(JSON_H) \
  $(KRYPTOHASH_CORE_H)

libkryptohash_wallet_a_SOURCES = \
  db.cpp \
  crypter.cpp \
  rpcdump.cpp \
  rpcwallet.cpp \
  wallet.cpp \
  walletdb.cpp \
  $(KRYPTOHASH_CORE_H)

libkryptohash_common_a_SOURCES = \
  base58.cpp \
  allocators.cpp \
  chainparams.cpp \
  core.cpp \
  genesis.cpp \
  hash.cpp \
  key.cpp \
  netbase.cpp \
  protocol.cpp \
  rpcprotocol.cpp \
  script.cpp \
  sync.cpp \
  util.cpp \
  version.cpp \
  $(KRYPTOHASH_CORE_H)

if GLIBC_BACK_COMPAT
libkryptohash_common_a_SOURCES += compat/glibc_compat.cpp
libkryptohash_common_a_SOURCES += compat/glibcxx_compat.cpp
endif

libkryptohash_cli_a_SOURCES = \
  rpcclient.cpp \
  $(KRYPTOHASH_CORE_H)

libkeccak_a_SOURCES = \
  keccak/sha3.c \
  keccak/KeccakRnd.c \
  keccak/KeccakHash.c \
  keccak/KeccakSponge.c \
  keccak/SnP/SnP-FBWL-default.c \
  $(KECCAK_H)
 
if USE_KECCAK64
 libkeccak_a_SOURCES += keccak/KeccakF-1600/Optimized64/KeccakF-1600-opt64.c
else
 libkeccak_a_SOURCES += keccak/KeccakF-1600/Inplace32BI/KeccakF-1600-inplace32BI.c
endif

if ! TARGET_WINDOWS
 libkeccak_a_CFLAGS="-fPIC"
endif
 
libed25519_a_SOURCES = \
  ed25519/ge.c \
  ed25519/fe.c \
  ed25519/sc.c \
  ed25519/keypair.c \
  ed25519/sign.c \
  ed25519/verify.c \
  $(ED25519_H)  

if ! TARGET_WINDOWS  
 libed25519_a_CFLAGS="-fPIC"
endif

nodist_libkryptohash_common_a_SOURCES = $(top_srcdir)/src/obj/build.h

#
# kryptohashd binary #
kryptohashd_LDADD = \
  libkryptohash_server.a \
  libkryptohash_cli.a \
  libkryptohash_common.a \
  libkeccak.a \
  libed25519.a \
  $(LIBLEVELDB) \
  $(LIBMEMENV)
if ENABLE_WALLET
kryptohashd_LDADD += libkryptohash_wallet.a
endif
kryptohashd_SOURCES = kryptohashd.cpp
#

if TARGET_WINDOWS
kryptohashd_SOURCES += kryptohashd-res.rc
endif

AM_CPPFLAGS += $(BDB_CPPFLAGS)
kryptohashd_LDADD += $(BOOST_LIBS) $(BDB_LIBS)

# kryptohash-cli binary #
kryptohash_cli_LDADD = \
  libkryptohash_cli.a \
  libkryptohash_common.a \
  libkeccak.a \
  libed25519.a \
  $(BOOST_LIBS)
kryptohash_cli_SOURCES = kryptohash-cli.cpp
#

if TARGET_WINDOWS
kryptohash_cli_SOURCES += kryptohash-cli-res.rc
endif

# NOTE: This dependency is not strictly necessary, but without it make may try to build both in parallel, which breaks the LevelDB build system in a race
leveldb/libleveldb.a: leveldb/libmemenv.a

leveldb/%.a:
	@echo "Building LevelDB ..." && $(MAKE) -C $(@D) $(@F) CXX="$(CXX)" \
	  CC="$(CC)" PLATFORM=$(TARGET_OS) AR="$(AR)" $(LEVELDB_TARGET_FLAGS) \
	  OPT="$(CXXFLAGS) $(CPPFLAGS)"

qt/kryptohashstrings.cpp: $(libkryptohash_server_a_SOURCES) $(libkryptohash_common_a_SOURCES) $(libkryptohash_cli_a_SOURCES)
	@test -n $(XGETTEXT) || echo "xgettext is required for updating translations"
	@cd $(top_srcdir); XGETTEXT=$(XGETTEXT) share/qt/extract_strings_qt.py

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a *.gcda *.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb Makefile.include

clean-local:
	-$(MAKE) -C leveldb clean
	rm -f leveldb/*/*.gcno leveldb/helpers/memenv/*.gcno
