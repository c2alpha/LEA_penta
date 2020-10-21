#include <string.h>
#include "LEA.h"

// 인풋을 2-dim array 형식으로 받는다고 치면.. pt[그런 개수][원래 평문 크기]이런거에다가
//뒷쪽이 꽉 찰때마다 앞에가 하나 증가하는 형식으로 될테고
//그게 아니고 단순 array로 가면 그냥 pt[길이] 이럴텐데 그럼 길이를 16으로 나눠봐야
//몇 개의 128-bit 평문이 묶인건지 알 수 있단 말이지
// 뭘로 할지는 내 자유일거같고 
// 이것보다 사실 패딩이 더 문제같은데 첫번째 방식으로 평문을 받는다면 pt[마지막]의 뒤쪽
// index가 어떻게 되는지만 보면 될 것 같단 말이지...

// 그래서 일단 인풋을 어찌 받을건데...
// 동적할당을 쓰나?? => 그렇다함

//####################################################################
//padding

//해야함.



//####################################################################
//ECB

void ECB_LEA_Enc(unsigned char ct[][LEA_BLOCK_LEN], const unsigned char pt[][LEA_BLOCK_LEN],
    const unsigned char MasterKey[LEA_MAX_KEY_LEN], const int KeyBytes)
{
    uint32_t RK[LEA_MAX_RNDS][LEA_MAX_KEY_LEN];
    int LEA_Rounds=LEA_Key_Schedule(RK,MasterKey,KeyBytes);
    int cnt=sizeof(pt)/16;
    for (int i = 0; i < cnt; i++)
    {
         LEA_Encryption(ct[i],pt[i],RK,LEA_Rounds);
    }
    
}

void ECB_LEA_Dec(unsigned char pt[][LEA_BLOCK_LEN], const unsigned char ct[][LEA_BLOCK_LEN],
    const unsigned char MasterKey[LEA_MAX_KEY_LEN], const int KeyBytes)
{
    uint32_t RK[LEA_MAX_RNDS][LEA_MAX_KEY_LEN];
    int LEA_Rounds=LEA_Key_Schedule(RK,MasterKey,KeyBytes);
    int cnt=sizeof(ct)/16;
    for (int i = 0; i < cnt; i++)
    {
        LEA_Decryption(pt[i],ct[i],RK,LEA_Rounds);
    }
    
}

//####################################################################
//CBC

// void CBC_LEA_Enc(unsigned char ct[][LEA_BLOCK_LEN], const unsigned char pt[][LEA_BLOCK_LEN],
// const unsigned char MasterKey[LEA_MAX_KEY_LEN], const char IV[LEA_BLOCK_LEN] )
// {


// }

// void CBC_LEA_Dec(unsigned char pt[][LEA_BLOCK_LEN], const unsigned char ct[][LEA_BLOCK_LEN],
// const unsigned char MasterKey[LEA_MAX_KEY_LEN], const char IV[LEA_BLOCK_LEN])
// {


// }






//####################################################################
//CTR

// void CTR_LEA_Enc(unsigned char ct[][LEA_BLOCK_LEN], const unsigned char pt[][LEA_BLOCK_LEN],
//     const unsigned char MasterKey[LEA_MAX_KEY_LEN], const char IV[LEA_BLOCK_LEN])
// {

// }

// void CTR_LEA_Dec(unsigned char pt[][LEA_BLOCK_LEN], const unsigned char ct[][LEA_BLOCK_LEN],
//     const unsigned char MasterKey[LEA_MAX_KEY_LEN], const char IV[LEA_BLOCK_LEN])
// {

// }