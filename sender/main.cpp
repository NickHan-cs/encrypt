#include "sender.h"
#include "rsa.h"
#include <gmp.h>
#include "../aes/AES.h"
#include "sha256.h"
#include <string>
#include <iostream>
#include <stdlib.h>
using namespace std;
void genSeed(int clnt_sock, mpz_t outseed)
{

    struct public_key *pub = new public_key;    //公钥结构体
    struct private_key *priv = new private_key; //私钥结构体
    //产生密钥
    RSA_gen_keys(pub, priv);
    gmp_printf("Public_key:\nmodulus:%ZX\n\nexponent:%ZX\n\n", pub->modulus, pub->exponent);
    gmp_printf("\nPrivate_key:\nmodulus:%ZX\n\nexponent:%ZX\n\n", priv->modulus, priv->exponent);
    char PublicKey[2048];
    gmp_sprintf(PublicKey, "%ZX", pub->modulus);
    int len = strlen((const char *)PublicKey);
    gmp_sprintf(PublicKey + len, ",%ZX\0", pub->exponent);
    int PublicKeyLen = strlen((const char *)PublicKey);

    sendKey((unsigned char *)PublicKey, PublicKeyLen, clnt_sock);

    unsigned char buffer[1280];
    memset(buffer, 0, sizeof(buffer));
    unsigned char *s_b = buffer;
    recvSeed(s_b, 1280, clnt_sock);

    mpz_t seed;
    mpz_init(seed);
    int enSeedLen = strlen((const char *)buffer);

    gmp_sscanf((const char *)buffer, "%ZX", seed);
    gmp_printf("EncryptedSeed:\n%ZX\n", seed);

    mpz_t outSeedNum;
    mpz_init(outSeedNum);
    RSA_decrypt(outSeedNum, seed, priv);
    mpz_set(outseed, outSeedNum);
    FILE *fp;
    fp = fopen("../seed.txt", "w+");
    gmp_fprintf(fp, "%ZX", outSeedNum);
    fclose(fp);
}
int main(int argc, char *argv[])
{

    if (argc != 4)
    {
        cout << "argc:" << argc << endl;
        return -1;
    }
    char *ipAddr = argv[1];      //目的IP地址
    int portNum = atoi(argv[2]); //目的端口
    char *filePath = argv[3];    //要传送的文件地址

    cout << "ipAddr:" << ipAddr << ",portNum:" << portNum << ",filePath:" << filePath << endl;
    int clnt_sock = socket(AF_INET, SOCK_STREAM, 0);
    printf("clnt_sock:%d\n", clnt_sock);
    //connect sender
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;                //ipv4
    serv_addr.sin_addr.s_addr = inet_addr(ipAddr); //ip address
    serv_addr.sin_port = htons(portNum);           //port
    int result = connect(clnt_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (result == -1)
    {
        printf("errno for connection is %d\n", errno);
    }
    else
    {
        printf("connection built!\n");
    }
    mpz_t outSeedNum;
    mpz_init(outSeedNum);

    FILE *seedFp;
    seedFp = fopen("../seed.txt", "r");
    if (seedFp == NULL) //若种子文件不存在
    {
        cout << "随机种子文件不存在，协商中..." << endl;
        genSeed(clnt_sock, outSeedNum);
    }
    else //否则，直接读取
    {
        gmp_fscanf(seedFp, "%ZX", outSeedNum);
        gmp_printf("随机种子文件存在，值为:%ZX\n", outSeedNum);
    }
    char outseed[128];
    memset(outseed, 0, sizeof(outseed));
    gmp_sprintf(outseed, "%ZX", outSeedNum);

    unsigned char aesSeed[32]; //If you use no-padding while encrypting the origin seed, it must be 128bytes, but we only need the first 32bytes.
    strncpy((char *)aesSeed, (const char *)outseed, 32);
    AES aes(aesSeed, 32);

    printf("Negotiation completes.\n");
    unsigned char path[4097];
    unsigned char fname[4097];
    unsigned char data_to_encrypt[16];
    unsigned char data_after_encrypt[16];
    unsigned char *dae;
    unsigned long fsize;
    unsigned char *msg;
    unsigned char digset[SHA256_MESSAGE_SIZE];
    sha256_context ctx;
    unsigned char sha_path[4097] = "sha256.txt";
    unsigned long sha_size;
    int i;
    FILE *sha;

    FILE *fp;
    if ((fp = fopen((const char *)filePath, "rb")) == NULL)
    {
        printf("File error!\n");
        return -1;
    }
    printf("File opening...\n");
    fseek(fp, SEEK_SET, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // sha256
    msg = (unsigned char *)malloc((fsize + 1) * sizeof(char));
    fsize = fread(msg, 1, fsize, fp);
    msg[fsize] = '\0';
    sha256_starts(&ctx);
    sha256_update(&ctx, msg, fsize);
    sha256_result(&ctx, digset);
    fseek(fp, 0, SEEK_SET);
    sha = fopen("./sha256.txt", "w");
    for (i = 0; i < SHA256_MESSAGE_SIZE; i++)
    {
        fprintf(sha, "%x", digset[i]);
    }
    fclose(sha);
    free(msg);
    sha = fopen("./sha256.txt", "rb");
    fseek(sha, SEEK_SET, SEEK_END);
    sha_size = ftell(sha);
    fseek(sha, 0, SEEK_SET);
    memset(data_to_encrypt, 0, sizeof(data_to_encrypt));
    mySendFile(sha, sha_size, sha_path, data_to_encrypt, data_after_encrypt, aes, clnt_sock);
    fclose(sha);

    memset(data_to_encrypt, 0, sizeof(data_to_encrypt));
    mySendFile(fp, fsize, (unsigned char *)filePath, data_to_encrypt, data_after_encrypt, aes, clnt_sock);

    fclose(fp);
    //关闭连接
    close(clnt_sock);
    return 0;
}
