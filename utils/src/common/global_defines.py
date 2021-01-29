# Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
#

# Definitions for sw version legal values -
#########################################
SW_REVOCATION_MAX_NUM_OF_BITS_HBK0 = 64
SW_REVOCATION_MAX_NUM_OF_BITS_HBK1 = 96
SW_REVOCATION_MAX_NUM_OF_BITS_HBK2 = 160

# HASH size in SHA256 in bytes
HASH_SHA256_DIGEST_SIZE_IN_BYTES = 32
HASH_ALGORITHM_SHA256_SIZE_IN_WORDS = 8

# Size of SW versions
SW_VERSION_OBJ_SIZE_IN_WORDS = 1

SOC_ID_SIZE_IN_BYTES = 32
SOC_ID_SIZE_IN_WORDS = 8

# certificate output file prefix
Cert_FileName = "Cert"
# certificate output file suffix
Cert_FileExtBin = ".bin"
Cert_FileExtTxt = ".txt"

# definitions for code encryption
AES_IV_SIZE_IN_BYTES = 16
AES_DECRYPT_KEY_SIZE_IN_BYTES = 16
SW_COMP_FILE_NAME_POSTFIX = "_enc.bin"

NONCE_SIZE_IN_WORDS = 2
MAX_NUM_OF_IMAGES = 16

SW_REC_ADDR32_SIGNED_DATA_SIZE_IN_WORDS = 3

USE_AES_CE_ID_NONE = 0
USE_AES_CE_ID_KCEICV = 1
USE_AES_CE_ID_KCE = 2

LOAD_AND_VERIFY_IMAGE = 0
VERIFY_IMAGE_IN_FLASH = 1
VERIFY_IMAGE_IN_MEM = 2
LOADING_ONLY_IMAGE = 3
