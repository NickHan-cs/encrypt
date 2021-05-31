
#include <gmp.h>
#include "receiver.h"
#include "rsa.h"
#include <ctime>
#include "../aes/AES.h"
#include "sha256.h"
#include <string>
#include <iostream>
#include <stdlib.h>
using namespace std;
typedef struct Ret
{
	int sock;
	AES aes;
} Ret;
//用于建立连接
Ret build(int serv_sock)
{
	printf("Sender socket ready.\n");
	printf("Waiting for connection...\n");
	int sock = waitForConnection(serv_sock);
	printf("Connection built.\n");

	FILE *seedFp;
	seedFp = fopen("../seed.txt", "r");
	mpz_t outSeedNum;
	mpz_init(outSeedNum);
	mpz_t seedNum;
	mpz_init(seedNum);
	unsigned char seed[1280], outseed[1280];
	if (seedFp == NULL) //若种子文件不存在，则进行协商
	{
		cout << "随机种子文件不存在，协商中..." << endl;
		unsigned char buffer[100000];
		unsigned char *b_f = buffer;
		int32_t pk_len = 0;
		recvPKeyAndLen(b_f, &pk_len, sock);
		//printf("ReceivedPublicKey:%s\n",buffer);
		struct public_key pub[1];
		gmp_sscanf((const char *)buffer, "%ZX,%ZX", pub->modulus, pub->exponent);
		gmp_printf("Public_key:\n\nmodulus:%ZX\n\nexponent:%ZX\n\n", pub->modulus, pub->exponent);

		gmp_randstate_t grt;
		gmp_randinit_default(grt);
		gmp_randseed_ui(grt, time(NULL));
		mpz_urandomb(seedNum, grt, 128);
		gmp_printf("OriginSeed:%ZX\n\n", seedNum);
		//RSA解密
		RSA_encrypt(outSeedNum, seedNum, pub);
		gmp_printf("EncryptedSeed:%ZX\n\n", outSeedNum);
		memset(seed, 0, 1280);
		memset(outseed, 0, 1280);

		gmp_sprintf((char *)seed, "%ZX\0", seedNum);
		gmp_sprintf((char *)outseed, "%ZX\0", outSeedNum);
		//发送Seed
		sendSeed(outseed, 1280, sock);
		FILE *wSeedFp = fopen("../seed.txt", "w+");
		gmp_fprintf(wSeedFp, "%ZX", seedNum);
		fclose(wSeedFp);
	}
	else
	{ //否则，直接读取原Seed
		gmp_fscanf(seedFp, "%ZX", seedNum);
		gmp_printf("随机种子文件存在，值为:%ZX\n", seedNum);
		gmp_sprintf((char *)seed, "%ZX\0", seedNum);
	}
	unsigned char aesSeed[32];
	strncpy((char *)aesSeed, (const char *)seed, 32);
	AES aes(aesSeed, 32);
	Ret r{sock, aes};
	return r;
}
int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		cout << "argc:" << argc << endl;
		return -1;
	}
	char *ipAddr = argv[1];		 //自身IP地址
	int portNum = atoi(argv[2]); //自身监听端口
	cout << "ipAddr:" << ipAddr << ",portNum:" << portNum << endl;

	int serv_sock = getServerSocket(ipAddr, portNum);

	Ret r = build(serv_sock);
	int sock = r.sock;
	AES aes = r.aes;
	unsigned char data_after_encrypt[16];
	unsigned char data_after_decrypt[16];

	char fn[256];
	unsigned long fsize;
	unsigned char *msg;
	unsigned char digset[SHA256_MESSAGE_SIZE];
	unsigned long sha_size;
	int i;
	FILE *fp;
	FILE *sha;
	char sha_rec[64];
	char sha_gen[64];
	sha256_context ctx;

	while (1)
	{
		//接收的第一个文件是sha256文件
		printf("Wainting For File...\n");
		memset(data_after_encrypt, 0, sizeof(data_after_encrypt));
		memset(data_after_decrypt, 0, sizeof(data_after_decrypt));
		myRecvFile(data_after_encrypt, data_after_decrypt, aes, sock, fn);

		//第二个文件是数据文件
		printf("Wainting For File...\n");
		memset(data_after_encrypt, 0, sizeof(data_after_encrypt));
		memset(data_after_decrypt, 0, sizeof(data_after_decrypt));
		myRecvFile(data_after_encrypt, data_after_decrypt, aes, sock, fn);
		//对数据文件进行SHA检验
		{
			fp = fopen((const char *)fn, "r");
			fseek(fp, SEEK_SET, SEEK_END);
			fsize = ftell(fp);
			fseek(fp, 0, SEEK_SET);
			msg = (unsigned char *)malloc((fsize + 1) * sizeof(char));
			fsize = fread(msg, 1, fsize, fp);
			msg[fsize] = '\0';
			sha256_starts(&ctx);
			sha256_update(&ctx, msg, fsize);
			sha256_result(&ctx, digset);
			fseek(fp, 0, SEEK_SET);
			sha = fopen("./sha256_gen.txt", "w");
			for (i = 0; i < SHA256_MESSAGE_SIZE; i++)
			{
				fprintf(sha, "%x", digset[i]);
			}
			fclose(sha);
			fclose(fp);
			free(msg);
			fp = fopen("./sha256.txt", "r");
			sha = fopen("./sha256_gen.txt", "r");
			fread(sha_rec, 1, 63, fp);
			fread(sha_gen, 1, 63, sha);
			sha_rec[63] = '\0';
			sha_gen[63] = '\0';
			if (strcmp(sha_rec, sha_gen) != 0)
			{
				printf("sha_rec:%s\n", sha_rec);
				printf("sha_gen:%s\n", sha_gen);
				printf("\n SHA256 Check Failed\n");
			}
			else
			{
				printf("\n SHA256 Check Success\n");
			}
		}
		//关闭当前sock，等待下一次的连接建立
		close(sock);

		r = build(serv_sock);
		sock = r.sock;
		aes = r.aes;
	}
	//关闭连接
	close(sock);
	close(serv_sock);
	return 0;
}
