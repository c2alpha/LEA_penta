#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "LEA.h"

#define MAX_MARKER_LEN      50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE* infile, const char* marker);
int		ReadHex(FILE* infile, unsigned char* A, int Length, char* str);
void	fprintBstr(FILE* fp, char* S, unsigned char* A, unsigned long long L);

int main()
{
	char fn_req[32], fn_rsp[32];
	FILE *fp_req, *fp_rsp;
	unsigned char pt[LEA_BLOCK_LEN], ct[LEA_BLOCK_LEN], decrypted[LEA_BLOCK_LEN];
	unsigned char mk[LEA_MAX_KEY_LEN];// 파일로부터 마스터키 받을거
	int done;

	// Create the Reponse file
	sprintf(fn_rsp, "LEA%d_KAT.rsp", 128);
	if ((fp_rsp = fopen(fn_rsp, "w")) == NULL)
	{
		printf("Couldn't open <%s> for write\n", fn_rsp);
		return KAT_FILE_OPEN_ERROR;
	}
	
	
	if ((fp_req = fopen("LEA128(ECB)KAT.req", "r")) == NULL)
	{
		printf("Couldn't open <%s> for read\n", fn_req);
		return KAT_FILE_OPEN_ERROR;
	}

	done = 0;
	do{
		// Write on the Response file based on what's in the request file
		if (!ReadHex(fp_req, mk, 16, "KEY = "))
		{
			done = 1;
			break;
		}
		fprintBstr(fp_rsp, "KEY = ", mk, 16);

		if (!ReadHex(fp_req, pt, 16, "PT = "))
		{
			printf("ERROR : unable to read 'PT' from <%s>\n", fn_req);
			done = 1;
			return KAT_DATA_ERROR;
		}
		fprintBstr(fp_rsp, "PT = ", pt, 16);

		// Generate the ciphertext on response file
		ECB_LEA_Enc(ct, pt, mk, 1, 16);
		fprintBstr(fp_rsp, "CT = ", ct, 16);

		fprintf(fp_rsp, "\n");

		ECB_LEA_Dec(decrypted, ct, mk, 1, 16);
		if (memcmp(decrypted, pt, 16))
		{
			printf("Crypto alg fail\n");
			done = 1;
		}
		

	} while (!done);

	fclose(fp_req);
	fclose(fp_rsp);

	return KAT_SUCCESS;
}


// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
int FindMarker(FILE* infile, const char* marker)
{
	char line[MAX_MARKER_LEN];
	int	i, len;
	int curr_line;

	len = (int)strlen(marker);
	if (len > MAX_MARKER_LEN - 1)
		len = MAX_MARKER_LEN - 1;

	for (i = 0; i < len; i++)
	{
		curr_line = fgetc(infile);
		line[i] = curr_line;
		if (curr_line == EOF)
			return 0;
	}
	line[len] = '\0';

	while (1) {
		if (!strncmp(line, marker, len))
			return 1;

		for (i = 0; i < len - 1; i++)
			line[i] = line[i + 1];
		curr_line = fgetc(infile);
		line[len - 1] = curr_line;
		if (curr_line == EOF)
			return 0;
		line[len] = '\0';
	}

	// shouldn't get here
	return 0;
}

int ReadHex(FILE* infile, unsigned char* A, int Length, char* str)
{
	int	i, ch, started;
	unsigned char ich;

	if (Length == 0) {
		A[0] = 0x00;
		return 1;
	}
	memset(A, 0x00, Length);
	started = 0;
	if (FindMarker(infile, str))
		while ((ch = fgetc(infile)) != EOF)
		{
			if (!isxdigit(ch))
			{
				if (!started)
				{
					if (ch == '\n')
						break;
					else
						continue;
				}
				else
					break;
			}
			started = 1;
			if ((ch >= '0') && (ch <= '9'))
				ich = ch - '0';
			else if ((ch >= 'A') && (ch <= 'F'))
				ich = ch - 'A' + 10;
			else if ((ch >= 'a') && (ch <= 'f'))
				ich = ch - 'a' + 10;
			else // shouldn't ever get here
				ich = 0;

			for (i = 0; i < Length - 1; i++)
				A[i] = (A[i] << 4) | (A[i + 1] >> 4);
			A[Length - 1] = (A[Length - 1] << 4) | ich;
		}
	else
		return 0;

	return 1;
}

void fprintBstr(FILE* fp, char* S, unsigned char* A, unsigned long long L)
{
	unsigned long long i;

	fprintf(fp, "%s", S);

	for (i = 0; i < L; i++)
		fprintf(fp, "%02X", A[i]);

	if (L == 0)
		fprintf(fp, "00");

	fprintf(fp, "\n");
}


