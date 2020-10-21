#include <stdint.h>

#define LEA_128_RNDS           24
#define LEA_128_KEY_LEN        16

#define LEA_192_RNDS           28
#define LEA_192_KEY_LEN        24

#define LEA_256_RNDS           32
#define LEA_256_KEY_LEN        32

#define LEA_MAX_RNDS           32
#define LEA_MAX_KEY_LEN        32
#define LEA_BLOCK_LEN          16
#define LEA_RNDKEY_WORD_LEN    6   // 한 라운드에 6개 필요



int LEA_Key_Schedule(uint32_t RndKeys[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN],
	const unsigned char MasterKey[LEA_MAX_KEY_LEN],
	const int KeyBytes);

void LEA_Encryption(unsigned char ct[LEA_BLOCK_LEN], const unsigned char pt[LEA_BLOCK_LEN],
	uint32_t RndKeys[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN], const int Nr);

void LEA_Decryption(unsigned char pt[LEA_BLOCK_LEN], const unsigned char ct[LEA_BLOCK_LEN],
	uint32_t RndKeys[LEA_MAX_RNDS][LEA_RNDKEY_WORD_LEN], const int Nr);