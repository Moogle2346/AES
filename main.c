/**
 * @file main.c
 * @brief メイン処理
 */

#include "typedefine.h"
#include "AES.h"

//-----------------------------------------------------------
//  マクロ定義
//-----------------------------------------------------------


//-----------------------------------------------------------
//  型定義
//-----------------------------------------------------------


//-----------------------------------------------------------
//  プロトタイプ宣言
//-----------------------------------------------------------


//-----------------------------------------------------------
//  変数定義
//-----------------------------------------------------------


//-----------------------------------------------------------
//  関数定義
//-----------------------------------------------------------

/**
 * @brief メイン処理
 * 
 */
void main(void)
{
	U8 plainText[32];
	U8 cipherText[32];
	U8 data[32];
	U8 i;

	plainText[0] = 0x00;
	plainText[1] = 0x11;
	plainText[2] = 0x22;
	plainText[3] = 0x33;
	plainText[4] = 0x44;
	plainText[5] = 0x55;
	plainText[6] = 0x66;
	plainText[7] = 0x77;
	plainText[8] = 0x88;
	plainText[9] = 0x99;
	plainText[10] = 0xAA;
	plainText[11] = 0xBB;
	plainText[12] = 0xCC;
	plainText[13] = 0xDD;
	plainText[14] = 0xEE;
	plainText[15] = 0xFF;
	plainText[16] = 0x00;
	plainText[17] = 0x11;
	plainText[18] = 0x22;
	plainText[19] = 0x33;
	plainText[20] = 0x44;
	plainText[21] = 0x55;
	plainText[22] = 0x66;
	plainText[23] = 0x77;
	plainText[24] = 0x88;
	plainText[25] = 0x99;
	plainText[26] = 0xAA;
	plainText[27] = 0xBB;
	plainText[28] = 0xCC;
	plainText[29] = 0xDD;
	plainText[30] = 0xEE;
	plainText[31] = 0xFF;

	while (1)
	{
		InitializeCryption();
		// Encrypt(plainText, cipherText, 2);
		for (i = 0; i < 2; i++)
		{
			Encrypt(&plainText[i * 16], &cipherText[i * 16], 1);
		}
		
		InitializeCryption();
		// Decrypt(cipherText, data, 2);
		for (i = 0; i < 2; i++)
		{
			Decrypt(&cipherText[i * 16], &data[i * 16], 1);
		}
	}
}