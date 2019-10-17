/*
 * Copyright (c) 2001-2019, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
 */

#ifndef _CMPU_HW_DEFS_H
#define _CMPU_HW_DEFS_H

#include "cc_regs.h"
#include "dx_host.h"
#include "cc_hal_plat.h"


#define CC_PROD_AIB_ADDR_REG_READ_ACCESS_BIT_SHIFT    0x10UL
#define CC_PROD_AIB_ADDR_REG_WRITE_ACCESS_BIT_SHIFT   0x11UL

#define SCC_OTP_CTRL_REG_OFFSET 0x204

#define CC_PROD_ROT32(val) ( (val) >> 16 | (val) << 16 )
#define CC_PROD_CONVERT_WORD_END(val) ( ((CC_PROD_ROT32((val)) & 0xff00ff00UL) >> 8) | ((CC_PROD_ROT32((val)) & 0x00ff00ffUL) << 8) )
#ifdef BIG__ENDIAN
/* inverse the bytes order in a word */
#define CC_PROD_SET_WORD_AS_LE(val) ( CC_PROD_CONVERT_WORD_END(val) )
#define CC_PROD_SET_WORD_AS_BE(val) (val)
#else
#define CC_PROD_SET_WORD_AS_LE(val) (val)
#define CC_PROD_SET_WORD_AS_BE(val) ( CC_PROD_CONVERT_WORD_END(val) )
#endif

/* Poll on the AIB bit */
#define CC_PROD_WAIT_ON_AIB_PROG_COMP_BIT() \
do {\
    uint32_t regVal;\
    do {\
        regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, AIB_FUSE_PROG_COMPLETED));\
    }while( !(regVal & 0x1 ));\
}while(0)


/* poll NVM register to be assure that the NVM boot is finished (and LCS and the keys are valid) */
#define WAIT_NVM_IDLE() \
    do {                                            \
        uint32_t regVal;                                \
        do {                                        \
            regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, NVM_IS_IDLE));            \
            regVal = CC_REG_FLD_GET(0, NVM_IS_IDLE, VALUE, regVal);         \
        }while( !regVal );                              \
    }while(0)

/* calc OTP memory length:
   read RTL OTP address width. The supported sizes are 6 (for 2 Kbits),7,8,9,10,11 (for 64 Kbits).
   convert value parameter to addresses of 32b words */
#define GET_OTP_LENGTH(otpLength)                           \
    do {                                                \
        WAIT_NVM_IDLE(); \
        otpLength = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, OTP_ADDR_WIDTH_DEF));  \
        otpLength = CC_REG_FLD_GET(0, OTP_ADDR_WIDTH_DEF, VALUE, otpLength);            \
        otpLength = (1 << 8 << (otpLength - 6));                               \
    }while(0)


/* read scc otp control register */
#define GET_SCC_OTP_CONTROL(otp_control) \
    do { \
        otp_control = (*((volatile uint32_t *)(DX_SCC_BASE_ADDR + SCC_OTP_CTRL_REG_OFFSET))); \
    }while(0)
/*******************************************************  OTP defines  ******************************************************/
/* read a word directly from OTP memory */
#define  CC_PROD_OTP_READ(otpData, otpWordOffset)                           \
    do {                                                                                \
        otpData = CC_HAL_READ_REGISTER( CC_OTP_BASE_ADDR + ((otpWordOffset)*CC_32BIT_WORD_SIZE));   \
    }while(0)

/* write a word directly from OTP memory */
#define CC_PROD_OTP_WRITE(otpData, otpWordOffset)                           \
    do {                                                                                \
        CC_HAL_WRITE_REGISTER(( CC_OTP_BASE_ADDR + ((otpWordOffset)*CC_32BIT_WORD_SIZE)), otpData); \
        CC_PROD_WAIT_ON_AIB_PROG_COMP_BIT();                                    \
    }while(0)


#define CC_PROD_OTP_WRITE_VERIFY_WORD(otpWordOffset, wordValue, rc) {\
    uint32_t  otpActualVal = 0;\
        if (wordValue != 0x0) { \
                CC_PROD_OTP_WRITE((wordValue), (otpWordOffset));\
            CC_PROD_OTP_READ(otpActualVal, (otpWordOffset));\
                if (otpActualVal !=(wordValue)) {\
                        rc = CC_PROD_HAL_FATAL_ERR;\
                } else { \
                     rc = CC_OK;\
                }\
        } \
        rc = CC_OK;\
}

#define CC_PROD_OTP_WRITE_VERIFY_WORD_BUFF(otpWordOffset, wordBuff, buffWordSize, rc) {\
    uint32_t  ii = 0;\
    for (ii =0; ii < (buffWordSize); ii++) { \
           CC_PROD_OTP_WRITE_VERIFY_WORD((otpWordOffset+ii), wordBuff[ii], rc); \
           if (rc != CC_OK) { \
                break; \
           } \
        } \
}


#define SET_OTP_MANUFACTURE_FLAG(manufactorWord, bitField, fieldValue)  \
                        BITFIELD_SET(manufactorWord,                             \
                                            CC_OTP_MANUFACTURE_FLAG_ ## bitField ## _BIT_SHIFT,  \
                                            CC_OTP_MANUFACTURE_FLAG_ ## bitField ## _BIT_SIZE,   \
                                            fieldValue)

#define SET_OTP_OEM_FLAG(manufactorWord, bitField, fieldValue)  \
                        BITFIELD_SET(manufactorWord,                             \
                                            CC_OTP_OEM_FLAG_ ## bitField ## _BIT_SHIFT,  \
                                            CC_OTP_OEM_FLAG_ ## bitField ## _BIT_SIZE,   \
                                            fieldValue)

#define IS_HBK0_USED(icvWord)  (BITFIELD_GET(icvWord,      \
                                                              CC_OTP_MANUFACTURE_FLAG_HBK0_NOT_IN_USE_BIT_SHIFT, \
                                                              CC_OTP_MANUFACTURE_FLAG_HBK0_NOT_IN_USE_BIT_SIZE) == 0)



#endif // _PROD_HW_DEFS_H

