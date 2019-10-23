/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 */


/*!
 @addtogroup cc_hash_defs
 @{
*/

/*!
 @file
 @brief This file contains definitions of the CryptoCell hash APIs.
 */

#ifndef CC_HASH_DEFS_H
#define CC_HASH_DEFS_H


#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_common_types_plat.h"
#include "cc_hash_defs_proj.h"
#include "cc_hash_common_defs.h"

/************************ Defines ******************************/

/************************ Typedefs  *****************************/

/*! The hash result buffer. */
typedef uint32_t CCHashResultBuf_t[CC_HASH_RESULT_SIZE_IN_WORDS];

/************************ Structs  ******************************/
/*!
 The context prototype of the user.
 The argument type that is passed by the user to the hash APIs.
 The context saves the state of the operation, and must be saved by the user
 until the end of the API flow.
*/
typedef struct CCHashUserContext_t {
    /*! The internal buffer. */
    uint32_t buff[CC_HASH_USER_CTX_SIZE_IN_WORDS];
}CCHashUserContext_t;


#ifdef __cplusplus
}
#endif

/*!
 @}
 */
#endif /* #ifndef CC_HASH_DEFS_H */
