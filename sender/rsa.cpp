#include "rsa.h"
#include <ctime>
//struct public_key{
//    mpz_t modulus;
//    mpz_t exponent;
//};
//struct private_key{
//    mpz_t modulus;
//    mpz_t exponent;
//};
//产生公钥与私钥
void RSA_gen_keys(struct public_key *pub, struct private_key *priv)
{
	//初始化随机状态
	gmp_randstate_t grt;
	gmp_randinit_default(grt);
	gmp_randseed_ui(grt, time(NULL));
	//初始化两个大素数
	mpz_t p, q;
	mpz_init(p);
	mpz_init(q);

	mpz_urandomb(p, grt, 1024);
	mpz_urandomb(q, grt, 1024);
	//产生两个大素数
	mpz_nextprime(p, p);
	mpz_nextprime(q, q);
	gmp_printf("Prime1:%ZX\n\n", p);
	gmp_printf("Prime2:%ZX\n\n", q);

	mpz_t n;
	mpz_init(n);
	mpz_mul(n, p, q);

	mpz_t phi;
	mpz_init(phi);
	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
	mpz_mul(phi, p, q);

	mpz_t e;
	mpz_init_set_ui(e, 65537);
	mpz_init(pub->modulus);
	mpz_init(pub->exponent);
	mpz_set(pub->modulus, n);
	mpz_set(pub->exponent, e);

	mpz_t d;
	mpz_init(d);
	mpz_invert(d, e, phi);
	mpz_init(priv->modulus);
	mpz_init(priv->exponent);
	mpz_set(priv->modulus, n);
	mpz_set(priv->exponent, d);
}
//加密
void RSA_encrypt(mpz_t outseed, mpz_t seed, const struct public_key *pub)
{
	mpz_t C;
	mpz_init(C);
	mpz_powm(C, seed, pub->exponent, pub->modulus);
	mpz_set(outseed, C);
	//gmp_printf("M=====>\n%ZX\n",seed);
	//gmp_printf("e=====>\n%ZX\n",pub->exponent);
	//gmp_printf("n=====>\n%ZX\n",pub->modulus);
	//gmp_printf("C=====>\n%ZX\n",outseed);
}
//解密
void RSA_decrypt(mpz_t outseed, mpz_t seed, const struct private_key *priv)
{
	mpz_t M;
	mpz_init(M);
	mpz_powm(M, seed, priv->exponent, priv->modulus);
	mpz_set(outseed, M);
	//gmp_printf("C=====>\n%ZX\n",seed);
	//gmp_printf("d=====>\n%ZX\n",priv->exponent);
	//gmp_printf("n=====>\n%ZX\n",priv->modulus);
	//gmp_printf("M=====>\n%ZX\n",outseed);
}