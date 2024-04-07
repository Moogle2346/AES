/**
 * @file AES.c
 * @brief AES暗号処理
 */

#include "typedefine.h"
#include "AES.h"
#include "AESAlgorithm.h"

//-----------------------------------------------------------
//  マクロ定義
//-----------------------------------------------------------


//-----------------------------------------------------------
//  型定義
//-----------------------------------------------------------


//-----------------------------------------------------------
//  プロトタイプ宣言
//-----------------------------------------------------------

static void InitializeIV(void);

//-----------------------------------------------------------
//  変数定義
//-----------------------------------------------------------

/**
 * @brief 暗号鍵
 * 
 */
static const U8 KEY[KEY_SIZE] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const U8 IV_DEFAULT[BLOCK_SIZE] =
{
	0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
	0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0
};

static U8 iv[BLOCK_SIZE];

//-----------------------------------------------------------
//  関数定義
//-----------------------------------------------------------

/**
 * @brief 暗号化処理の初期化を行います。
 * @note 暗号・復号処理の前に必ず実行してください。
 *       ただし暗号・復号を分割して行う場合は全ての処理が完了するまで初期化しないこと。
 */
void InitializeCryption(void)
{
	InitializeIV();
	CreateExpansionKey(KEY);
}

#ifdef USE_ENCRYPTION
/**
 * @brief AES128で暗号化します。
 * @param[in] plainText 平文
 * @param[out] cipherText 暗号文
 * @param[in] block ブロック数(1ブロック=16Byte)
 * @note ivを初期化しない限り暗号化を複数の処理に分割可能
 */
void Encrypt(U8 *plainText, U8 *cipherText, U32 block)
{
	EncryptByAES128(plainText, cipherText, block, iv);
}
#endif	// USE_ENCRYPTION

#ifdef USE_DECRYPTION
/**
 * @brief AES128で復号します。
 * @param[in] cipherText 暗号文
 * @param[out] plainText 平文
 * @param[in] block ブロック数(1ブロック=16Byte)
 * @note ivを初期化しない限り復号を複数の処理に分割可能
 */
void Decrypt(U8 *cipherText, U8 *plainText, U32 block)
{
	DecryptByAES128(cipherText, plainText, block, iv);
}
#endif	// USE_DECRYPTION

/**
 * @brief IVをデフォルト値に設定します。
 * 
 */
static void InitializeIV(void)
{
	U8 i;

	for (i = 0; i < BLOCK_SIZE; i++)
	{
		iv[i] = IV_DEFAULT[i];
	}
}
