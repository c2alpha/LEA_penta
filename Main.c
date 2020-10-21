#include <stdio.h>
#include "LEA.h"

int main()
{
    unsigned char Master_Key_128[16] = { 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
                                         0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0 };
    unsigned char Master_Key_192[24] = { 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
                                         0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
                                         0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87 };
    unsigned char Master_Key_256[32] = { 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
                                         0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
                                         0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
                                         0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f };
    unsigned char P_text_128[16] = { 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };
    unsigned char P_text_192[16] = { 0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f };
    unsigned char P_text_256[16] = { 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f };
    unsigned char C_text_128[16] = { 0, };
    unsigned char C_text_192[16] = { 0, };
    unsigned char C_text_256[16] = { 0, };
    uint32_t rk[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN];


    printf("Key schedule-128\n");
    LEA_Key_Schedule(rk, Master_Key_128, LEA_128_KEY_LEN);
    for (int i = 0; i < LEA_128_RNDS; i++)
    {
        printf("RK %d\n", i);
        for (int j = 0; j < 6; j++)
        {
            printf("%08x ", rk[i][j]);
        }
        printf("\n");
    }

    printf("\nEncryption-128\n");
    LEA_Encryption(C_text_128, P_text_128, rk, LEA_128_RNDS);


    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", C_text_128[i]);
    }
    printf("\n");

    printf("\nDecryption-128\n");
    LEA_Decryption(P_text_128, C_text_128, rk, LEA_128_RNDS);
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", P_text_128[i]);
    }
    printf("\n\n\n\n");



    printf("Key schedule-192\n");
    LEA_Key_Schedule(rk, Master_Key_192, LEA_192_KEY_LEN);
    for (int i = 0; i < LEA_192_RNDS; i++)
    {
        printf("RK %d\n", i);
        for (int j = 0; j < 6; j++)
        {
            printf("%08x ", rk[i][j]);
        }
        printf("\n");
    }

    printf("\nEncryption-192\n");
    LEA_Encryption(C_text_192, P_text_192, rk, LEA_192_RNDS);
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", C_text_192[i]);
    }
    printf("\n");

    printf("\nDecryption-192\n");
    LEA_Decryption(P_text_192, C_text_192, rk, LEA_192_RNDS);
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", P_text_192[i]);
    }
    printf("\n\n\n\n");



    printf("Key schedule-256\n");
    LEA_Key_Schedule(rk, Master_Key_256, LEA_256_KEY_LEN);
    for (int i = 0; i < LEA_256_RNDS; i++)
    {
        printf("RK %d\n", i);
        for (int j = 0; j < 6; j++)
        {
            printf("%08x ", rk[i][j]);
        }
        printf("\n");
    }

    printf("\nEncryption-256\n");
    LEA_Encryption(C_text_256, P_text_256, rk, LEA_256_RNDS);


    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", C_text_256[i]);
    }
    printf("\n");

    printf("\nDecryption-256\n");
    LEA_Decryption(P_text_256, C_text_256, rk, LEA_256_RNDS);
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", P_text_256[i]);
    }
    printf("\n\n\n\n");

}