#!/usr/bin/env python3
#
# Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
#

import optparse
import configparser
import sys
import struct
import os
import logging
sys.path.append(os.path.join(sys.path[0], "..", ".."))

from common import loggerinitializer
from common import cryptolayer

# Util's log file
LOG_FILENAME = "key_response_cert.log"

# This utility enables the ICV to build the encrypted OEM temporary key


class ArgumentParser:
    def __init__(self):
        self.cfg_filename = None
        self.log_filename = LOG_FILENAME
        self.parser = optparse.OptionParser(usage="usage: %prog cfg_file [log_filename]")

    def parse_arguments(self):
        (options, args) = self.parser.parse_args()
        if len(args) > 2 or len(args) < 1:
            self.parser.error("incorrect number of positional arguments")
        elif len(args) == 2:
            self.log_filename = args[1]
        self.cfg_filename = args[0]


class IcvKeyResponseConfig:
    CFG_SECTION_NAME = "DMPU-ICV-KEY-RES-CFG"

    def __init__(self):
        self._oem_cert_pkg = None
        self._key_filename = None
        self._keypwd_filename = ""
        self._icv_enc_oem_key = None

    @property
    def section_name(self):
        return self.CFG_SECTION_NAME

    @property
    def oem_cert_pkg(self):
        return self._oem_cert_pkg

    @oem_cert_pkg.setter
    def oem_cert_pkg(self, value):
        if isinstance(value, str) is False:
            raise TypeError("Config parameter oem-cert-pkg must be a string")
        elif value == "":
            raise ValueError("Config parameter oem-cert-pkg cannot be an empty string!")
        else:
            self._oem_cert_pkg = value

    @property
    def key_filename(self):
        return self._key_filename

    @key_filename.setter
    def key_filename(self, value):
        if isinstance(value, str) is False:
            raise TypeError("Config parameter key-filename must be a string")
        elif value == "":
            raise ValueError("Config parameter key-filename cannot be an empty string!")
        else:
            self._key_filename = value

    @property
    def keypwd_filename(self):
        return self._keypwd_filename

    @keypwd_filename.setter
    def keypwd_filename(self, value):
        if isinstance(value, str) is False:
            raise TypeError("Config parameter keypwd-filename must be a string")
        else:
            self._keypwd_filename = value

    @property
    def icv_enc_oem_key(self):
        return self._icv_enc_oem_key

    @icv_enc_oem_key.setter
    def icv_enc_oem_key(self, value):
        if isinstance(value, str) is False:
            raise TypeError("Config parameter icv-enc-oem-key must be a string")
        elif value == "":
            raise ValueError("Config parameter icv-enc-oem-key cannot be an empty string!")
        else:
            self._icv_enc_oem_key = value


class IcvKeyResponseConfigParser:

    def __init__(self, config_filename):
        self.config_filename = config_filename
        self.config = configparser.ConfigParser()
        self.logger = logging.getLogger()
        self._config_holder = IcvKeyResponseConfig()

    def get_config(self):
        return self._config_holder

    def parse_config(self):
        self.logger.info("Parsing config file: " + self.config_filename)
        self.config.read(self.config_filename)

        if not self.config.has_section(self._config_holder.section_name):
            self.logger.warning("section [" + self._config_holder.section_name + "] wasn't found in cfg file")
            return False

        if not self.config.has_option(self._config_holder.section_name, 'oem-cert-pkg'):
            self.logger.warning("oem-cert-pkg not found")
            return False
        else:
            self._config_holder.oem_cert_pkg = self.config.get(self._config_holder.section_name, 'oem-cert-pkg')

        if not self.config.has_option(self._config_holder.section_name, 'key-filename'):
            self.logger.warning("key-filename not found")
            return False
        else:
            self._config_holder.key_filename = self.config.get(self._config_holder.section_name, 'key-filename')

        if self.config.has_option(self._config_holder.section_name, 'keypwd-filename'):
            self._config_holder.keypwd_filename = self.config.get(self._config_holder.section_name, 'keypwd-filename')

        if not self.config.has_option(self._config_holder.section_name, 'icv-enc-oem-key'):
            self.logger.warning("icv-enc-oem-key not found")
            return False
        else:
            self._config_holder.icv_enc_oem_key = self.config.get(self._config_holder.section_name, 'icv-enc-oem-key')

        return True


class KeyResponsePackageCreator:
    OEM_KEY_REQ_CERT_SIZE = 1204
    DMPU_OEM_KEY_REQ_TOKEN = 0x52455144
    DMPU_OEM_KEY_REQ_VERSION = 0x01
    KRTL_SIZE = 16
    PROD_OEM_KEY_TMP_LABEL = "KEY OEM"
    PUBKEY_SIZE_BYTES = 384  # 3072 bits
    NP_SIZE_IN_BYTES = 20
    DMPU_CERT_HEADER_SIZE_IN_BYTES = 12

    def __init__(self, key_response_cfg):
        self.config = key_response_cfg
        self.logger = logging.getLogger()

    def create_package(self):
        with open(self.config.oem_cert_pkg, "rb") as cert_package:
            cert_data = cert_package.read()
        cert_data_size = len(cert_data)
        if cert_data_size != self.OEM_KEY_REQ_CERT_SIZE:
            self.logger.warning("Invalid certificate size: " + str(cert_data_size))
            sys.exit(-1)

        with open(self.config.key_filename, "rb") as krtl_key_file:
            krtl_key = krtl_key_file.read()
        krtl_key_size = len(krtl_key)
        if krtl_key_size != 2 * self.KRTL_SIZE:
            self.logger.warning("Invalid key size: " + str(krtl_key_size))
            sys.exit(-1)

        #  verify the certificate
        if cert_data[0:4] != struct.pack('<I', self.DMPU_OEM_KEY_REQ_TOKEN):
            self.logger.warning("Invalid token field in certificate header: " + str(cert_data[0:4]))
            sys.exit(-1)
        if cert_data[4:8] != struct.pack('<I', self.DMPU_OEM_KEY_REQ_VERSION):
            self.logger.warning("Invalid version field in certificate header: " + str(cert_data[4:8]))
            sys.exit(-1)
        if cert_data[8:12] != struct.pack('<I', self.OEM_KEY_REQ_CERT_SIZE - self.PUBKEY_SIZE_BYTES):
            self.logger.warning("Invalid length field in certificate header: " + str(cert_data[8:12]))
            sys.exit(-1)
        # verify certificate
        oem_enc_pubkey_field_start = 12 + cryptolayer.RsaCrypto.SB_CERT_RSA_KEY_SIZE_IN_BYTES + cryptolayer.RsaCrypto.NP_SIZE_IN_BYTES
        oem_rsa_public_key_params = cert_data[12:oem_enc_pubkey_field_start]
        oem_rsa_public_key_param_n = oem_rsa_public_key_params[0:cryptolayer.RsaCrypto.SB_CERT_RSA_KEY_SIZE_IN_BYTES]
        cert_signed_data_length = self.DMPU_CERT_HEADER_SIZE_IN_BYTES + 2 * (self.PUBKEY_SIZE_BYTES + self.NP_SIZE_IN_BYTES)
        cryptolayer.Common.rsa_verify_with_pubkey_params(oem_rsa_public_key_param_n,
                                                         cert_data[0:cert_signed_data_length],
                                                         cert_data[cert_signed_data_length:])

        self.logger.info("**** Generate OEM key package ****")
        # decrypt Krtl
        decrypted_krtl_key = cryptolayer.Common.decrypt_asset_with_aes_cbc(krtl_key, self.config.keypwd_filename)
        # Calculate HBK from oem main public key hash
        hbk_value = cryptolayer.HashCrypto.calculate_sha256_hash(oem_rsa_public_key_params)
        # calculate Ktmp = cmac(Krtl, 0x01 || OEM_label  || 0x0 || HBK(only 16 bytes) || 0x80)
        input_data = (struct.pack('B', 0x01)
                      + self.PROD_OEM_KEY_TMP_LABEL.encode('utf-8')
                      + struct.pack('B', 0)
                      + hbk_value[0:16]
                      + struct.pack('B', 0x80))  # outkeysize in bits
        key_tmp = cryptolayer.AesCrypto.calc_aes_cmac(input_data, decrypted_krtl_key)
        # Encrypt the OEM key with the dedicated key pair
        oem_enc_pubkey_params_from_cert = cert_data[oem_enc_pubkey_field_start:
                                                    (oem_enc_pubkey_field_start
                                                     + cryptolayer.RsaCrypto.SB_CERT_RSA_KEY_SIZE_IN_BYTES
                                                     + cryptolayer.RsaCrypto.NP_SIZE_IN_BYTES)]
        encrypted_key = cryptolayer.Common.encrypt_data_with_rsa_pubkey_params(oem_enc_pubkey_params_from_cert, key_tmp)

        # write package to output file
        with open(self.config.icv_enc_oem_key, "wb") as package_outfile:
            package_outfile.write(encrypted_key)


if __name__ == "__main__":
    if not (sys.version_info.major == 3 and sys.version_info.minor >= 5):
        sys.exit("The script requires Python3.5 or later!")
    # parse arguments
    the_argument_parser = ArgumentParser()
    the_argument_parser.parse_arguments()
    # get logging up and running
    logger_config = loggerinitializer.LoggerInitializer(the_argument_parser.log_filename)
    logger = logging.getLogger()
    # get util configuration parameters
    config_parser = IcvKeyResponseConfigParser(the_argument_parser.cfg_filename)
    if config_parser.parse_config() is False:
        logger.critical("Config file parsing is not successful")
        sys.exit(-1)
    # create secure asset package
    asset_provisioner = KeyResponsePackageCreator(config_parser.get_config())
    asset_provisioner.create_package()
    logger.info("**** ICV key response generation has been completed successfully ****")
