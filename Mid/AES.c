/**
 * @file AES.c
 * @brief AES�Í�����
 */

#include "typedefine.h"
#include "AES.h"
#include "AESAlgorithm.h"

//-----------------------------------------------------------
//  �}�N����`
//-----------------------------------------------------------


//-----------------------------------------------------------
//  �^��`
//-----------------------------------------------------------


//-----------------------------------------------------------
//  �v���g�^�C�v�錾
//-----------------------------------------------------------

static void InitializeIV(void);

//-----------------------------------------------------------
//  �ϐ���`
//-----------------------------------------------------------

/**
 * @brief �Í���
 * 
 */
static const U8 key[KEY_SIZE] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	// 0x2B, 0x28, 0xAB, 0x09, 0x7E, 0xAE, 0xF7, 0xCF,
	// 0x15, 0xD2, 0x15, 0x4F, 0x16, 0xa6, 0x88, 0x3C
};

static const U8 iv_default[BLOCK_SIZE] =
{
	0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
	0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0
};

static U8 iv[BLOCK_SIZE];

//-----------------------------------------------------------
//  �֐���`
//-----------------------------------------------------------

/**
 * @brief �Í��������̏��������s���܂��B�Í��E���������̑O�ɕK�����s���Ă��������B
 * 
 */
void InitializeCryption(void)
{
	InitializeIV();
	CreateExpansionKey(key);
}

/**
 * @brief AES128�ňÍ������܂��B
 * @param plainText ����
 * @param cipherText �Í���
 * @param block �u���b�N�T�C�Y(1�u���b�N=16Byte)
 */
void Encrypt(U8 *plainText, U8 *cipherText, U32 block)
{
	EncryptByAES128(plainText, cipherText, block, iv);
}

/**
 * @brief AES128�ŕ������܂��B
 * @param plainText ����
 * @param cipherText �Í���
 * @param length �T�C�Y
 */
void Decrypt(U8 *cipherText, U8 *plainText, U32 block)
{
	DecryptByAES128(cipherText, plainText, block, iv);
}

/**
 * @brief IV���f�t�H���g�l�ɐݒ肵�܂��B
 * 
 */
static void InitializeIV(void)
{
	U8 i;

	for (i = 0; i < BLOCK_SIZE; i++)
	{
		iv[i] = iv_default[i];
	}
}