CC=gcc
CFLAGS=-Ofast -Wall -Wno-unused-function -Wno-pointer-sign \
       -I. -Isecp256k1 -Isecp256k1/include -funsafe-loop-optimizations
LDFLAGS=$(CFLAGS)
LDLIBS=-lm -lgmp -lpthread

SHA256=sha256/sha256.o sha256/sha256-avx-asm.o sha256/sha256-avx2-asm.o \
       sha256/sha256-ssse3-asm.o sha256/sha256-ni-asm.o

OBJS=keygen.o base58.o rmd160.o $(SHA256)


all: keygen

install: all
	cp --remove-destination -p keygen /usr/local/bin/

clean:
	rm -f keygen *.o sha256/*.o

distclean: clean
	$(MAKE) -C secp256k1 distclean


keygen: $(OBJS)

$(OBJS): Makefile *.h secp256k1/src/libsecp256k1-config.h secp256k1/src/ecmult_static_context.h

secp256k1/src/libsecp256k1-config.h:
	(cd secp256k1;./autogen.sh;./configure)

secp256k1/src/ecmult_static_context.h:
	$(MAKE) -C secp256k1 src/ecmult_static_context.h
