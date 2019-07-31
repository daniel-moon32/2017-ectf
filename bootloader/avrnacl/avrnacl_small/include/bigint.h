#ifndef BIGINT_H
#define BIGINT_H

#define bigint_add avrnacl_bigint_add
#define bigint_add64 avrnacl_bigint_add64
#define bigint_and64 avrnacl_bigint_and64
#define bigint_xor64 avrnacl_bigint_xor64
#define bigint_not64 avrnacl_bigint_not64
#define bigint_ror64 avrnacl_bigint_ror64
#define bigint_shr64 avrnacl_bigint_shr64

/* Arithmetic on big integers represented as arrays of unsigned char */

extern char bigint_add(unsigned char* r, const unsigned char* a, const unsigned char* b, int length);

extern char bigint_add64(unsigned char* r, const unsigned char* a, const unsigned char* b);

extern char bigint_and64(unsigned char* r, const unsigned char* a, const unsigned char* b);

extern char bigint_xor64(unsigned char* r, const unsigned char* a, const unsigned char* b);

extern char bigint_not64(unsigned char* r, const unsigned char* a);

extern char bigint_ror64(unsigned char* r, unsigned char length);

extern char bigint_shr64(unsigned char* r, unsigned char length);

#endif
