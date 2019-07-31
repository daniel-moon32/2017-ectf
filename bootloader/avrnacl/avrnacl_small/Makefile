include ../config

CFLAGS = -g -Wall -Wextra -Werror -mmcu=$(TARGET_DEVICE) -Os -I../randombytes/ -I.. -I./include/ -DF_CPU=$(CPUFREQ) -mcall-prologues

all: obj/libnacl.a

obj/libnacl.a: obj/crypto_stream/salsa20.o \
 							 obj/crypto_stream/xsalsa20.o \
 							 obj/crypto_core/hsalsa20.o \
 							 obj/crypto_core/salsa20.o \
 							 obj/crypto_core/salsa_core.o \
 							 obj/crypto_verify/verify.o \
 							 obj/crypto_hashblocks/sha512.o \
 							 obj/crypto_hashblocks/sha512_core.o \
 							 obj/crypto_hash/sha512.o \
							 obj/shared/consts.o \
							 obj/shared/bigint_add.o \
							 obj/shared/bigint_add64.o \
							 obj/shared/bigint_and64.o \
							 obj/shared/bigint_xor64.o \
							 obj/shared/bigint_ror64.o \
							 obj/shared/bigint_shr64.o \
							 obj/shared/bigint_not64.o
	$(AR) cr obj/libnacl.a $^


obj/crypto_stream/%.o: crypto_stream/%.[cS]
	mkdir -p obj/crypto_stream
	$(CC) $(CFLAGS) -c $^ -o $@

obj/crypto_core/%.o: crypto_core/%.[cS]
	mkdir -p obj/crypto_core
	$(CC) $(CFLAGS) -c $^ -o $@

obj/crypto_verify/%.o: crypto_verify/%.[cS]
	mkdir -p obj/crypto_verify
	$(CC) $(CFLAGS) -c $^ -o $@

obj/crypto_hashblocks/%.o: crypto_hashblocks/%.[cS]
	mkdir -p obj/crypto_hashblocks
	$(CC) $(CFLAGS) -c $^ -o $@

obj/crypto_hash/%.o: crypto_hash/%.[cS]
	mkdir -p obj/crypto_hash
	$(CC) $(CFLAGS) -c $^ -o $@

obj/crypto_auth/%.o: crypto_auth/%.[cS]
	mkdir -p obj/crypto_auth
	$(CC) $(CFLAGS) -c $^ -o $@

obj/shared/%.o: shared/%.[cS]
	mkdir -p obj/shared
	$(CC) $(CFLAGS) -c $^ -o $@

obj/randombytes.o: ../randombytes/randombytes.c
	mkdir -p obj/
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY: clean

clean:
	-rm -r obj/*
