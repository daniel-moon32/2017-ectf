/*
 * File:    avrnacl.h
 * Author:  Michael Hutter, Peter Schwabe
 * Version: Tue Aug 12 08:23:16 2014 +0200
 * Public Domain
 */

#ifndef AVRNACL_H
#define AVRNACL_H

typedef char crypto_int8;
typedef unsigned char crypto_uint8;
typedef int crypto_int16;
typedef unsigned int crypto_uint16;
typedef long crypto_int32;
typedef unsigned long crypto_uint32;
typedef long long crypto_int64;
typedef unsigned long long crypto_uint64;

#define crypto_core_PRIMITIVE "salsa20"
#define crypto_core_salsa20_OUTPUTBYTES 64
#define crypto_core_salsa20_INPUTBYTES 16
#define crypto_core_salsa20_KEYBYTES 32
#define crypto_core_salsa20_CONSTBYTES 16
extern int crypto_core_salsa20(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);

#define crypto_core_hsalsa20_OUTPUTBYTES 32
#define crypto_core_hsalsa20_INPUTBYTES 16
#define crypto_core_hsalsa20_KEYBYTES 32
#define crypto_core_hsalsa20_CONSTBYTES 16
extern int crypto_core_hsalsa20(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);

#define crypto_hashblocks_PRIMITIVE "sha512"
#define crypto_hashblocks_sha512_STATEBYTES 64
#define crypto_hashblocks_sha512_BLOCKBYTES 128
extern int crypto_hashblocks_sha512(unsigned char *,const unsigned char *,crypto_uint16);

#define crypto_hash_PRIMITIVE "sha512"
#define crypto_hash_sha512_BYTES 64
extern int crypto_hash_sha512(unsigned char *,const unsigned char *,crypto_uint16);

#define crypto_stream_PRIMITIVE "xsalsa20"
#define crypto_stream_xsalsa20_KEYBYTES 32
#define crypto_stream_xsalsa20_NONCEBYTES 24
extern int crypto_stream_xsalsa20_xor(unsigned char *,const unsigned char *,crypto_uint16,const unsigned char *,const unsigned char *);
extern int crypto_stream_salsa20_xor(unsigned char *,const unsigned char *,crypto_uint16,const unsigned char *,const unsigned char *);

#define crypto_verify_PRIMITIVE "32"
#define crypto_verify_32_BYTES 32
extern int crypto_verify_32(const unsigned char *,const unsigned char *);

#endif
