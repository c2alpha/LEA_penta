#include "LEA.h"

#define ROR(W,i)    (((uint32_t)(W)>>(int)(i)) | ((uint32_t)(W)<<(32-(int)(i))))
#define ROL(W,i)    (((uint32_t)(W)<<(int)(i)) | ((uint32_t)(W)>>(32-(int)(i))))
#define BTOW(x)     (((uint32_t)(x)[3] << 24) ^ ((uint32_t)(x)[2] << 16) ^ ((uint32_t)(x)[1] <<  8) ^ ((uint32_t)(x)[0]))
#define WTOB(x, v)  { (x)[3] = (unsigned char)((v) >> 24); (x)[2] = (unsigned char)((v) >> 16); (x)[1] = (unsigned char)((v) >>  8); (x)[0] = (unsigned char)(v); }

#define msb ((uint_least32_t) 0x80000000)
#define lsb ((uint_least32_t) 0x00000001)
#define MASK_WL ((uint_least32_t)0xFFFFFFFF)

const uint32_t delta[8] = { 0xc3efe9db,0x44626b02,0x79e27c8a,0x78df30ec,
                            0x715ea49e,0xc785da0a,0xe04ef22a,0xe5c40957 };

/*
* Name    : Lea_Key_Schedule
* Require : Master secret key which length is 128, 192, 256 bits for LEA-128, LEA-192, LEA-256 respectively
* Ensure  : Round keys which length is 24, 28, 32 bytes for LEA-128, LEA-192, LEA-256 respectively
*
* return value is round key length
*/
int LEA_Key_Schedule(uint32_t RndKeys[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN],
    const unsigned char MasterKey[LEA_MAX_KEY_LEN],
    const int KeyBytes)
{
    uint32_t T[8] = { 0x0, };
    int i;
    if (KeyBytes == LEA_128_KEY_LEN)//LEA-128
    {
        T[0] = BTOW(MasterKey);
        T[1] = BTOW(MasterKey + 4);
        T[2] = BTOW(MasterKey + 8);
        T[3] = BTOW(MasterKey + 12);
        for (i = 0; i < LEA_128_RNDS; i++)
        {
            T[0] = ROL(T[0] + ROL(delta[i & 3], i), 1);
            T[1] = ROL(T[1] + ROL(delta[i & 3], i + 1), 3);
            T[2] = ROL(T[2] + ROL(delta[i & 3], i + 2), 6);
            T[3] = ROL(T[3] + ROL(delta[i & 3], i + 3), 11);

            RndKeys[i][0] = T[0];
            RndKeys[i][1] = T[1];
            RndKeys[i][2] = T[2];
            RndKeys[i][3] = T[1];
            RndKeys[i][4] = T[3];
            RndKeys[i][5] = T[1];
        }

        return LEA_128_RNDS;
    }

    else if (KeyBytes == LEA_192_KEY_LEN)//LEA-192
    {
        T[0] = BTOW(MasterKey);
        T[1] = BTOW(MasterKey + 4);
        T[2] = BTOW(MasterKey + 8);
        T[3] = BTOW(MasterKey + 12);
        T[4] = BTOW(MasterKey + 16);
        T[5] = BTOW(MasterKey + 20);

        for (i = 0; i < LEA_192_RNDS; i++)
        {
            T[0] = ROL(T[0] + ROL(delta[i % 6], i & 0x1f), 1);
            T[1] = ROL(T[1] + ROL(delta[i % 6], (i + 1) & 0x1f), 3);
            T[2] = ROL(T[2] + ROL(delta[i % 6], (i + 2) & 0x1f), 6);
            T[3] = ROL(T[3] + ROL(delta[i % 6], (i + 3) & 0x1f), 11);
            T[4] = ROL(T[4] + ROL(delta[i % 6], (i + 4) & 0x1f), 13);
            T[5] = ROL(T[5] + ROL(delta[i % 6], (i + 5) & 0x1f), 17);

            RndKeys[i][0] = T[0];
            RndKeys[i][1] = T[1];
            RndKeys[i][2] = T[2];
            RndKeys[i][3] = T[3];
            RndKeys[i][4] = T[4];
            RndKeys[i][5] = T[5];
        }

        return LEA_192_RNDS;
    }

    else if (KeyBytes == LEA_256_KEY_LEN)//LEA-256
    {
        T[0] = BTOW(MasterKey);
        T[1] = BTOW(MasterKey + 4);
        T[2] = BTOW(MasterKey + 8);
        T[3] = BTOW(MasterKey + 12);
        T[4] = BTOW(MasterKey + 16);
        T[5] = BTOW(MasterKey + 20);
        T[6] = BTOW(MasterKey + 24);
        T[7] = BTOW(MasterKey + 28);

        for (i = 0; i < LEA_256_RNDS; i++)
        {
            T[(6 * i) & 7] = ROL(T[(6 * i) & 7] + ROL(delta[i & 7], i & 0x1f), 1);
            T[(6 * i + 1) & 7] = ROL(T[(6 * i + 1) & 7] + ROL(delta[i & 7], (i + 1) & 0x1f), 3);
            T[(6 * i + 2) & 7] = ROL(T[(6 * i + 2) & 7] + ROL(delta[i & 7], (i + 2) & 0x1f), 6);
            T[(6 * i + 3) & 7] = ROL(T[(6 * i + 3) & 7] + ROL(delta[i & 7], (i + 3) & 0x1f), 11);
            T[(6 * i + 4) & 7] = ROL(T[(6 * i + 4) & 7] + ROL(delta[i & 7], (i + 4) & 0x1f), 13);
            T[(6 * i + 5) & 7] = ROL(T[(6 * i + 5) & 7] + ROL(delta[i & 7], (i + 5) & 0x1f), 17);

            RndKeys[i][0] = T[(6 * i) & 7];
            RndKeys[i][1] = T[(6 * i + 1) & 7];
            RndKeys[i][2] = T[(6 * i + 2) & 7];
            RndKeys[i][3] = T[(6 * i + 3) & 7];
            RndKeys[i][4] = T[(6 * i + 4) & 7];
            RndKeys[i][5] = T[(6 * i + 5) & 7];
        }

        return LEA_256_RNDS;
    }

    return -1;

}


void LEA_Encryption(unsigned char ct[LEA_BLOCK_LEN], const unsigned char pt[LEA_BLOCK_LEN],
    uint32_t RndKeys[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN], const int Nr)
{
    uint32_t X0, X1, X2, X3;
    uint32_t temp;
    int i;

    X0 = BTOW(pt);
    X1 = BTOW(pt + 4);
    X2 = BTOW(pt + 8);
    X3 = BTOW(pt + 12);


    for (i = 0; i < Nr; i++)
    {
        temp = X0;
        X0 = ROL((X0 ^ RndKeys[i][0]) + (X1 ^ RndKeys[i][1]), 9);
        X1 = ROR((X1 ^ RndKeys[i][2]) + (X2 ^ RndKeys[i][3]), 5);
        X2 = ROR((X2 ^ RndKeys[i][4]) + (X3 ^ RndKeys[i][5]), 3);
        X3 = temp;
    }

    WTOB(ct, X0);
    WTOB(ct + 4, X1);
    WTOB(ct + 8, X2);
    WTOB(ct + 12, X3);
}

void LEA_Decryption(unsigned char pt[LEA_BLOCK_LEN], const unsigned char ct[LEA_BLOCK_LEN],
    uint32_t RndKeys[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN], const int Nr)
{
    uint32_t X0, X1, X2, X3;
    uint32_t temp0, temp1, temp2;
    int i;

    X0 = BTOW(ct);
    X1 = BTOW(ct + 4);
    X2 = BTOW(ct + 8);
    X3 = BTOW(ct + 12);

    for (i = 0; i < Nr; i++)
    {
        temp0 = X0;
        temp1 = X1;
        temp2 = X2;
        X0 = X3;
        X1 = (ROR(temp0, 9) - (X0 ^ RndKeys[Nr - 1 - i][0])) ^ RndKeys[Nr - 1 - i][1];
        X2 = (ROL(temp1, 5) - (X1 ^ RndKeys[Nr - 1 - i][2])) ^ RndKeys[Nr - 1 - i][3];
        X3 = (ROL(temp2, 3) - (X2 ^ RndKeys[Nr - 1 - i][4])) ^ RndKeys[Nr - 1 - i][5];

    }

    WTOB(pt, X0);
    WTOB(pt + 4, X1);
    WTOB(pt + 8, X2);
    WTOB(pt + 12, X3);
}





