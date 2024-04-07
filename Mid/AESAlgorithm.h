/**
 * @file AESAlgorithm.h
 * @brief AES暗号処理
 */

#ifndef AESALGORITHM_H
#define AESALGORITHM_H

//-----------------------------------------------------------
//  マクロ定義
//-----------------------------------------------------------

#define KEY_SIZE			(U8)(16)
#define BLOCK_SIZE			(U8)(16)

#define USE_ENCRYPTION
#define USE_DECRYPTION

//-----------------------------------------------------------
//  型定義
//-----------------------------------------------------------


//-----------------------------------------------------------
//  変数定義
//-----------------------------------------------------------


//-----------------------------------------------------------
//  プロトタイプ宣言
//-----------------------------------------------------------

void CreateExpansionKey(U8 *key);
#ifdef USE_ENCRYPTION
void EncryptByAES128(const U8 *plainText, U8 *cipherText, U32 block, U8 *iv);
#endif	// USE_ENCRYPTION
#ifdef USE_DECRYPTION
void DecryptByAES128(const U8 *cipherText, U8 *plainText, U32 block, U8 *iv);
#endif	// USE_DECRYPTION

#endif	// AESALGORITHM_H
