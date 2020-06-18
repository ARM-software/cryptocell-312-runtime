/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 */

#ifndef _SB_CC3X_X509_EXT_PARSER_H
#define _SB_CC3X_X509_EXT_PARSER_H

#include "stdint.h"
#include "secureboot_basetypes.h"
#include "bootimagesverifier_def.h"
#include "secdebug_defs.h"

/*!
 * @brief Parse certificate extension segment
 *
 * @param[in/out] ppCert 	    - pointer to X509 certificate as ASN.1 byte array
 * @param[in] certSize	 	    - certificate size
 * @param[in] ppCertPropHeader	- pointer to Certificate header
 * @param[in] ppNp       	    - pointer to Public key Np
 * @param[in] ppCertBody        - pointer to certificate body
 * @param[in] pCertBodySize	    - pointer to certificate body size
 * @param[in] startAddress  	- start address of certificate
 * @param[in] endAddress  	    - end address of certificate (the certificate pointer cannot exceed this address)
 *
 * @return uint32_t 		- On success: the value CC_OK is returned,
 *         			  On failure: a value from bsv_error.h
 */
CCError_t SB_X509_ParseCertExtensions(uint8_t 		**ppCert,
                                      uint32_t 		certSize,
                                      CCSbCertHeader_t **ppCertPropHeader,
                                      uint8_t 		**ppNp,
                                      uint8_t 		**ppCertBody,
                                      uint32_t	*pCertBodySize,
                                      unsigned long   startAddress,
                                      unsigned long   endAddress);

#endif
