/**
 * @file AESAlgorithm.c
 * @brief AES暗号アルゴリズム
 */

#include "typedefine.h"
#include "AESAlgorithm.h"

//-----------------------------------------------------------
//  マクロ定義
//-----------------------------------------------------------

#define WORD				(U8)(4)
#define KEY_SIZE_WORD		(U8)(KEY_SIZE / WORD)
#define MAX_ROUND			(U8)(10)
#define ROUND_KEY_SIZE		(U8)(WORD * (MAX_ROUND + 1))

//-----------------------------------------------------------
//  型定義
//-----------------------------------------------------------


//-----------------------------------------------------------
//  プロトタイプ宣言
//-----------------------------------------------------------

static U32 SubWord(U32 data);
static U32 RotWord(U32 data);
static void AddRoundKey(U8 *data, U32 *key);
static void SubBytes(U8 *data);
static U8 GetSBox(U8 num);
static void InvSubBytes(U8 *data);
static U8 GetInvSBox(U8 num);
static void ShiftRows(U8 *data);
static void InvShiftRows(U8 *data);
static void MixColumns(U8 *data);
static void InvMixColumns(U8 *data);
static U8 GMul(U8 a, U8 b);
static void CopyArrayData(U8 *dest , U8 *src, U32 size);

//-----------------------------------------------------------
//  変数定義
//-----------------------------------------------------------

const U32 rcon[11] = {
	0x00000000,		/* invalid */
	0x00000001,		/* x^0 */
	0x00000002,		/* x^1 */
	0x00000004,		/* x^2 */
	0x00000008,		/* x^3 */
	0x00000010,		/* x^4 */
	0x00000020,		/* x^5 */
	0x00000040,		/* x^6 */
	0x00000080,		/* x^7 */
	0x0000001B,		/* x^4 + x^3 + x^1 + x^0 */
	0x00000036 		/* x^5 + x^4 + x^2 + x^1 */
};

/**
 * @brief S-Box置換表
 * 
 */
static const U8 sbox[256] =
{
	0x63,	0x7c,	0x77,	0x7b,	0xf2,	0x6b,	0x6f,	0xc5,	0x30,	0x01,	0x67,	0x2b,	0xfe,	0xd7,	0xab,	0x76,
	0xca,	0x82,	0xc9,	0x7d,	0xfa,	0x59,	0x47,	0xf0,	0xad,	0xd4,	0xa2,	0xaf,	0x9c,	0xa4,	0x72,	0xc0,
	0xb7,	0xfd,	0x93,	0x26,	0x36,	0x3f,	0xf7,	0xcc,	0x34,	0xa5,	0xe5,	0xf1,	0x71,	0xd8,	0x31,	0x15,
	0x04,	0xc7,	0x23,	0xc3,	0x18,	0x96,	0x05,	0x9a,	0x07,	0x12,	0x80,	0xe2,	0xeb,	0x27,	0xb2,	0x75,
	0x09,	0x83,	0x2c,	0x1a,	0x1b,	0x6e,	0x5a,	0xa0,	0x52,	0x3b,	0xd6,	0xb3,	0x29,	0xe3,	0x2f,	0x84,
	0x53,	0xd1,	0x00,	0xed,	0x20,	0xfc,	0xb1,	0x5b,	0x6a,	0xcb,	0xbe,	0x39,	0x4a,	0x4c,	0x58,	0xcf,
	0xd0,	0xef,	0xaa,	0xfb,	0x43,	0x4d,	0x33,	0x85,	0x45,	0xf9,	0x02,	0x7f,	0x50,	0x3c,	0x9f,	0xa8,
	0x51,	0xa3,	0x40,	0x8f,	0x92,	0x9d,	0x38,	0xf5,	0xbc,	0xb6,	0xda,	0x21,	0x10,	0xff,	0xf3,	0xd2,
	0xcd,	0x0c,	0x13,	0xec,	0x5f,	0x97,	0x44,	0x17,	0xc4,	0xa7,	0x7e,	0x3d,	0x64,	0x5d,	0x19,	0x73,
	0x60,	0x81,	0x4f,	0xdc,	0x22,	0x2a,	0x90,	0x88,	0x46,	0xee,	0xb8,	0x14,	0xde,	0x5e,	0x0b,	0xdb,
	0xe0,	0x32,	0x3a,	0x0a,	0x49,	0x06,	0x24,	0x5c,	0xc2,	0xd3,	0xac,	0x62,	0x91,	0x95,	0xe4,	0x79,
	0xe7,	0xc8,	0x37,	0x6d,	0x8d,	0xd5,	0x4e,	0xa9,	0x6c,	0x56,	0xf4,	0xea,	0x65,	0x7a,	0xae,	0x08,
	0xba,	0x78,	0x25,	0x2e,	0x1c,	0xa6,	0xb4,	0xc6,	0xe8,	0xdd,	0x74,	0x1f,	0x4b,	0xbd,	0x8b,	0x8a,
	0x70,	0x3e,	0xb5,	0x66,	0x48,	0x03,	0xf6,	0x0e,	0x61,	0x35,	0x57,	0xb9,	0x86,	0xc1,	0x1d,	0x9e,
	0xe1,	0xf8,	0x98,	0x11,	0x69,	0xd9,	0x8e,	0x94,	0x9b,	0x1e,	0x87,	0xe9,	0xce,	0x55,	0x28,	0xdf,
	0x8c,	0xa1,	0x89,	0x0d,	0xbf,	0xe6,	0x42,	0x68,	0x41,	0x99,	0x2d,	0x0f,	0xb0,	0x54,	0xbb,	0x16
};

/**
 * @brief S-Box逆置換表
 * 
 */
static const U8 invSbox[256] =
{
	0x52,	0x09,	0x6a,	0xd5,	0x30,	0x36,	0xa5,	0x38,	0xbf,	0x40,	0xa3,	0x9e,	0x81,	0xf3,	0xd7,	0xfb,
	0x7c,	0xe3,	0x39,	0x82,	0x9b,	0x2f,	0xff,	0x87,	0x34,	0x8e,	0x43,	0x44,	0xc4,	0xde,	0xe9,	0xcb,
	0x54,	0x7b,	0x94,	0x32,	0xa6,	0xc2,	0x23,	0x3d,	0xee,	0x4c,	0x95,	0x0b,	0x42,	0xfa,	0xc3,	0x4e,
	0x08,	0x2e,	0xa1,	0x66,	0x28,	0xd9,	0x24,	0xb2,	0x76,	0x5b,	0xa2,	0x49,	0x6d,	0x8b,	0xd1,	0x25,
	0x72,	0xf8,	0xf6,	0x64,	0x86,	0x68,	0x98,	0x16,	0xd4,	0xa4,	0x5c,	0xcc,	0x5d,	0x65,	0xb6,	0x92,
	0x6c,	0x70,	0x48,	0x50,	0xfd,	0xed,	0xb9,	0xda,	0x5e,	0x15,	0x46,	0x57,	0xa7,	0x8d,	0x9d,	0x84,
	0x90,	0xd8,	0xab,	0x00,	0x8c,	0xbc,	0xd3,	0x0a,	0xf7,	0xe4,	0x58,	0x05,	0xb8,	0xb3,	0x45,	0x06,
	0xd0,	0x2c,	0x1e,	0x8f,	0xca,	0x3f,	0x0f,	0x02,	0xc1,	0xaf,	0xbd,	0x03,	0x01,	0x13,	0x8a,	0x6b,
	0x3a,	0x91,	0x11,	0x41,	0x4f,	0x67,	0xdc,	0xea,	0x97,	0xf2,	0xcf,	0xce,	0xf0,	0xb4,	0xe6,	0x73,
	0x96,	0xac,	0x74,	0x22,	0xe7,	0xad,	0x35,	0x85,	0xe2,	0xf9,	0x37,	0xe8,	0x1c,	0x75,	0xdf,	0x6e,
	0x47,	0xf1,	0x1a,	0x71,	0x1d,	0x29,	0xc5,	0x89,	0x6f,	0xb7,	0x62,	0x0e,	0xaa,	0x18,	0xbe,	0x1b,
	0xfc,	0x56,	0x3e,	0x4b,	0xc6,	0xd2,	0x79,	0x20,	0x9a,	0xdb,	0xc0,	0xfe,	0x78,	0xcd,	0x5a,	0xf4,
	0x1f,	0xdd,	0xa8,	0x33,	0x88,	0x07,	0xc7,	0x31,	0xb1,	0x12,	0x10,	0x59,	0x27,	0x80,	0xec,	0x5f,
	0x60,	0x51,	0x7f,	0xa9,	0x19,	0xb5,	0x4a,	0x0d,	0x2d,	0xe5,	0x7a,	0x9f,	0x93,	0xc9,	0x9c,	0xef,
	0xa0,	0xe0,	0x3b,	0x4d,	0xae,	0x2a,	0xf5,	0xb0,	0xc8,	0xeb,	0xbb,	0x3c,	0x83,	0x53,	0x99,	0x61,
	0x17,	0x2b,	0x04,	0x7e,	0xba,	0x77,	0xd6,	0x26,	0xe1,	0x69,	0x14,	0x63,	0x55,	0x21,	0x0c,	0x7d,
};

static const U8 matrix[16] =
{
	0x02,	0x03,	0x01,	0x01,
	0x01,	0x02,	0x03,	0x01,
	0x01,	0x01,	0x01,	0x02,
	0x03,	0x01,	0x01,	0x02
};

static const U8 InvMatrix[16] =
{
	0x0E,	0x0B,	0x0D,	0x09,
	0x09,	0x0E,	0x0B,	0x0D,
	0x0D,	0x09,	0x0E,	0x0B,
	0x0B,	0x0D,	0x09,	0x0E
};

static U32 roundKey[ROUND_KEY_SIZE];

//-----------------------------------------------------------
//  関数定義
//-----------------------------------------------------------

void CreateExpansionKey(U8 *key)
{
	U8 i;
	U32 tmp;

	for (i = 0; i < KEY_SIZE_WORD; i++)
	{
		roundKey[i] = *(U32*)&key[i * WORD];
	}

	for (i = KEY_SIZE_WORD; i < ROUND_KEY_SIZE; i++)
	{
		tmp = roundKey[i - 1];
		if (i % KEY_SIZE_WORD == 0)
		{
			tmp = SubWord(RotWord(tmp)) ^ rcon[i / KEY_SIZE_WORD];
		}
		else if ((6 < KEY_SIZE_WORD) && (i % KEY_SIZE_WORD == 4))
		{
			tmp = SubWord(tmp);
		}
		roundKey[i] = roundKey[i - KEY_SIZE_WORD] ^ tmp;
	}
}

static U32 SubWord(U32 data)
{
	U8 i;
	U8 tmp[WORD];
	U32 result;

	for (i = 0; i < WORD; i++)
	{
		tmp[i] = (U8)((data >> (i * 8)) & 0xFF);
		tmp[i] = GetSBox(tmp[i]);
	}

	return *(U32*)tmp;
}

static U32 RotWord(U32 data)
{
	/* a3 a2 a1 a0 -> a0 a3 a2 a1 */
	return data << 24 | data >> 8;
}

void EncryptByAES128(const U8 *plainText, U8 *cipherText, U32 block, U8 *iv)
{
	U8 i, j;
	U8 *plainTextPtr;
	U8 *cipherTextPtr;

	for (i = 0; i < block; i++)
	{
		plainTextPtr = &plainText[i * BLOCK_SIZE];
		cipherTextPtr = &cipherText[i * BLOCK_SIZE];

		for (j = 0; j < BLOCK_SIZE; j++)
		{
			cipherTextPtr[j] = plainTextPtr[j];
		}

		// 暗号処理
		AddRoundKey(cipherTextPtr, &roundKey[0]);

		for (j = 1; j < MAX_ROUND; j++)
		{
			SubBytes(cipherTextPtr);
			ShiftRows(cipherTextPtr);
			MixColumns(cipherTextPtr);
			AddRoundKey(cipherTextPtr, &roundKey[WORD * j]);
		}

		SubBytes(cipherTextPtr);
		ShiftRows(cipherTextPtr);
		AddRoundKey(cipherTextPtr, &roundKey[WORD * MAX_ROUND]);

		CopyArrayData(iv, cipherTextPtr, BLOCK_SIZE);
	}
}

void DecryptByAES128(const U8 *cipherText, U8 *plainText, U32 block, U8 *iv)
{
	U8 i, j, k;
	U8 *cipherTextPtr;
	U8 *plainTextPtr;

	for (i = 0; i < block; i++)
	{
		cipherTextPtr = &cipherText[i * BLOCK_SIZE];
		plainTextPtr = &plainText[i * BLOCK_SIZE];

		CopyArrayData(plainTextPtr, cipherTextPtr, BLOCK_SIZE);

		// 復号処理
		AddRoundKey(plainTextPtr, &roundKey[WORD * MAX_ROUND]);

		for (k = MAX_ROUND - 1; 0 < k; k--)
		{
			InvShiftRows(plainTextPtr);
			InvSubBytes(plainTextPtr);
			AddRoundKey(plainTextPtr, &roundKey[WORD * k]);
			InvMixColumns(plainTextPtr);
		}

		InvShiftRows(plainTextPtr);
		InvSubBytes(plainTextPtr);
		AddRoundKey(plainTextPtr, roundKey);

		CopyArrayData(iv, cipherTextPtr, BLOCK_SIZE);
	}
}

/****************************** AddRoundKey ******************************/

/**
 * @brief 引数にラウンドキーの排他的論理和を行います。
 * @param[out] data データ
 * @param[in] key ラウンドキー
 */
static void AddRoundKey(U8 *data, U32 *key)
{
	U8 i;

	for (i = 0; i < KEY_SIZE_WORD; i++)
	{
		((U32*)data)[i] ^= key[i];
	}
}

/****************************** SubBytes ******************************/

/**
 * @brief S-Boxに基づきデータを置換します。
 * @param[in] data 置換データ
 */
static void SubBytes(U8 *data)
{
	U8 i;

	for (i = 0; i < BLOCK_SIZE; i++)
	{
		data[i] = GetSBox(data[i]);
	}
}

/**
 * @brief S-Boxのデータを返します。
 * @param num 値
 * @return 置換データ
 */
static U8 GetSBox(U8 num)
{
	return sbox[num];
}

/**
 * @brief InvS-Boxに基づきデータを置換します。
 * @param data 置換データ
 */
static void InvSubBytes(U8 *data)
{
	U8 i;

	for (i = 0; i < BLOCK_SIZE; i++)
	{
		data[i] = GetInvSBox(data[i]);
	}
}

/**
 * InvS-Boxのデータを返します。
 * @param num 値
 * @return 置換データ
 */
static U8 GetInvSBox(U8 num)
{
	return invSbox[num];
}

/****************************** ShiftRows ******************************/

/**
 * @brief データの各要素を左にシフトします。
 * @param data データ配列
 */
static void ShiftRows(U8 *data)
{
	U8 tmp[16];
	U8 i;

	CopyArrayData(tmp, data, BLOCK_SIZE);

	data[0] = tmp[0];	data[4] = tmp[4];	data[8]  = tmp[8];	data[12] = tmp[12];		// 00 04 08 12 -> 00 04 08 12
	data[1] = tmp[5];	data[5] = tmp[9];	data[9]  = tmp[13];	data[13] = tmp[1];		// 01 05 09 13 -> 05 09 13 01
	data[2] = tmp[10];	data[6] = tmp[14];	data[10] = tmp[2];	data[14] = tmp[6];		// 02 06 10 14 -> 10 14 02 06
	data[3] = tmp[15];	data[7] = tmp[3];	data[11] = tmp[7];	data[15] = tmp[11];		// 03 07 11 15 -> 15 03 07 11
}

/**
 * @brief データの各要素を右にシフトします。
 * @param data データ配列
 */
static void InvShiftRows(U8 *data)
{
	U8 tmp[16];
	U8 i;

	CopyArrayData(tmp, data, BLOCK_SIZE);

	data[0] = tmp[0];	data[4] = tmp[4];	data[8]  = tmp[8];	data[12] = tmp[12];		// 00 04 08 12 -> 00 04 08 12
	data[1] = tmp[13];	data[5] = tmp[1];	data[9]  = tmp[5];	data[13] = tmp[9];		// 01 05 09 13 -> 13 01 05 09
	data[2] = tmp[10];	data[6] = tmp[14];	data[10] = tmp[2];	data[14] = tmp[6];		// 02 06 10 14 -> 10 14 02 06
	data[3] = tmp[7];	data[7] = tmp[11];	data[11] = tmp[15];	data[15] = tmp[3];		// 03 07 11 15 -> 07 11 15 03
}

/****************************** MixColumn ******************************/

static void MixColumns(U8 *data)
{
	U8 table[4][4];
	U8 tmp[4][4];
	U8 c;

	table[0][0] = data[0];	table[0][1] = data[4];	table[0][2] = data[8];	table[0][3] = data[12];
	table[1][0] = data[1];	table[1][1] = data[5];	table[1][2] = data[9];	table[1][3] = data[13];
	table[2][0] = data[2];	table[2][1] = data[6];	table[2][2] = data[10];	table[2][3] = data[14];
	table[3][0] = data[3];	table[3][1] = data[7];	table[3][2] = data[11];	table[3][3] = data[15];

	for (c = 0; c < 4; c++) {
		tmp[0][c] = (U8)(GMul(0x02, table[0][c]) ^ GMul(0x03, table[1][c]) ^ table[2][c]			 ^ table[3][c]);
		tmp[1][c] = (U8)(table[0][c] 			 ^ GMul(0x02, table[1][c]) ^ GMul(0x03, table[2][c]) ^ table[3][c]);
		tmp[2][c] = (U8)(table[0][c]			 ^ table[1][c]			   ^ GMul(0x02, table[2][c]) ^ GMul(0x03, table[3][c]));
		tmp[3][c] = (U8)(GMul(0x03, table[0][c]) ^ table[1][c]			   ^ table[2][c]			 ^ GMul(0x02, table[3][c]));
    }

	data[0] = tmp[0][0];	data[4] = tmp[0][1];	data[8]  = tmp[0][2];	data[12] = tmp[0][3];
	data[1] = tmp[1][0];	data[5] = tmp[1][1];	data[9]  = tmp[1][2];	data[13] = tmp[1][3];
	data[2] = tmp[2][0];	data[6] = tmp[2][1];	data[10] = tmp[2][2];	data[14] = tmp[2][3];
	data[3] = tmp[3][0];	data[7] = tmp[3][1];	data[11] = tmp[3][2];	data[15] = tmp[3][3];
}

static void InvMixColumns(U8 *data)
{
	U8 table[4][4];
	U8 tmp[4][4];
	U8 c;

	table[0][0] = data[0];	table[0][1] = data[4];	table[0][2] = data[8];	table[0][3] = data[12];
	table[1][0] = data[1];	table[1][1] = data[5];	table[1][2] = data[9];	table[1][3] = data[13];
	table[2][0] = data[2];	table[2][1] = data[6];	table[2][2] = data[10];	table[2][3] = data[14];
	table[3][0] = data[3];	table[3][1] = data[7];	table[3][2] = data[11];	table[3][3] = data[15];

	for (c = 0; c < 4; c++) {
		tmp[0][c] = (U8)(GMul(0x0E, table[0][c]) ^ GMul(0x0B, table[1][c]) ^ GMul(0x0D, table[2][c]) ^ GMul(0x09, table[3][c]));
		tmp[1][c] = (U8)(GMul(0x09, table[0][c]) ^ GMul(0x0E, table[1][c]) ^ GMul(0x0B, table[2][c]) ^ GMul(0x0D, table[3][c]));
		tmp[2][c] = (U8)(GMul(0x0D, table[0][c]) ^ GMul(0x09, table[1][c]) ^ GMul(0x0E, table[2][c]) ^ GMul(0x0B, table[3][c]));
		tmp[3][c] = (U8)(GMul(0x0B, table[0][c]) ^ GMul(0x0D, table[1][c]) ^ GMul(0x09, table[2][c]) ^ GMul(0x0E, table[3][c]));
    }

	data[0] = tmp[0][0];	data[4] = tmp[0][1];	data[8]  = tmp[0][2];	data[12] = tmp[0][3];
	data[1] = tmp[1][0];	data[5] = tmp[1][1];	data[9]  = tmp[1][2];	data[13] = tmp[1][3];
	data[2] = tmp[2][0];	data[6] = tmp[2][1];	data[10] = tmp[2][2];	data[14] = tmp[2][3];
	data[3] = tmp[3][0];	data[7] = tmp[3][1];	data[11] = tmp[3][2];	data[15] = tmp[3][3];
}

static U8 GMul(U8 a, U8 b)
{
    U8 p = 0;
	U8 counter;
	U8  hi_bit_set;

    for (counter = 0; counter < 8; counter++) {
        if ((b & 1) != 0) {
            p ^= a;
        }

		hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }

    return p;
}


/**
 * @brief 配列の要素を別の配列にコピーします。
 * @param dest コピー先
 * @param src コピー元
 * @param size 要素数
 */
static void CopyArrayData(U8 *dest , U8 *src, U32 size)
{
	U32 i;

	for (i = 0; i < size; i++)
	{
		dest[i] = src[i];
	}
}