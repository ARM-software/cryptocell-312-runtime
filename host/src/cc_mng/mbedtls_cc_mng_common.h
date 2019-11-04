/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 */

#ifndef _MBEDTLS_CC_MNG_COMMON_H
#define _MBEDTLS_CC_MNG_COMMON_H

/************************ Includes ******************************/
#include <stdint.h>

/************************ Enums ******************************/
/*! HASH boot key definition. */
typedef enum {
    CC_MNG_HASH_BOOT_KEY_0_128B         = 0,        /*!< 128-bit truncated SHA256 digest of public key 0. */
    CC_MNG_HASH_BOOT_KEY_1_128B     = 1,        /*!< 128-bit truncated SHA256 digest of public key 1. */
    CC_MNG_HASH_BOOT_KEY_256B       = 2,        /*!< 256-bit SHA256 digest of public key. */
    CC_MNG_HASH_BOOT_NOT_USED       = 0xF,
    CC_MNG_HASH_MAX_NUM                 = 0x7FFFFFFF,   /*!\internal use external 128-bit truncated SHA256 digest */
}mbedtls_mng_pubKeyType_t;

/************************ Defines ******************************/
/* LCS. */
/*! Chip manufacturer (CM LCS). */
#define CC_MNG_LCS_CM       0x0
/*! Device manufacturer (DM LCS). */
#define CC_MNG_LCS_DM       0x1
/*! Security enabled (Secure LCS). */
#define CC_MNG_LCS_SEC_ENABLED  0x5
/*! RMA (RMA LCS). */
#define CC_MNG_LCS_RMA      0x7

/************************ API's ******************************/
/*!
@brief This function reads an OTP word from from 'otpAddress' to 'pOtpWord'.

@return CC_OK on success.
@return A non-zero value from cc_manage.h on failure.
 */
int mbedtls_mng_otpWordRead(uint32_t otpAddress,            /*!< [in]       OTP Address: An Offset in Words in the OTP address space. */
                uint32_t *pOtpWord);            /*!< [in/out]   OTP Word pointer: An address to store the read Word. */

/*!
@brief This function returns the LCS value'.

@return CC_OK on success.
@return A non-zero value from cc_manage.h on failure.
 */
int mbedtls_mng_lcsGet(uint32_t *pLcs);                 /*!< [in/out]   LCS Value: An address to store the LCS Value. */

/*!
@brief This function reads software revocation counter from OTP memory, according to the provided key index.

@return CC_OK on success.
@return A non-zero value from cc_manage.h on failure.
*/
int mbedtls_mng_swVersionGet(
                mbedtls_mng_pubKeyType_t keyIndex,      /*!< [in] Enumeration defining the key hash to retrieve: 128-bit HBK0, 128-bit HBK1, or 256-bit HBK. */
    uint32_t *swVersion                                 /*!< [out] The value of the requested counter as read from OTP memory. */
    );

/*!
@brief This function retrieves the public key hash from OTP memory, according to the provided index.

@return CC_OK on success.
@return A non-zero value from cc_manage.h on failure.
*/
int mbedtls_mng_pubKeyHashGet(
                mbedtls_mng_pubKeyType_t keyIndex,      /*!< [in] Enumeration defining the key hash to retrieve: 128-bit HBK0, 128-bit HBK1, or 256-bit HBK. */
                uint32_t *hashedPubKey,                 /*!< [out] A buffer to contain the public key HASH. */
                uint32_t hashResultSizeWords            /*!< [in] The size of the hash in 32-bit words:
                                                        - Must be 4 for 128-bit hash.
                                                        - Must be 8 for 256bit hash. */
    );

#endif // _MBEDTLS_CC_MNG_COMMON_H
