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
sys.path.append(os.path.join(sys.path[0], ".."))

from common import loggerinitializer
from common import cryptolayer

# Util's log file
LOG_FILENAME = "icv_asset_pkg.log"

# This utility builds production asset  package:
# the package format is:
#                       token, version, asset length, user data (20 bytes)
#                       nonce(12 bytes)
#                       encrypted asset (up to 512 bytes - multiple of 16 bytes)
#                       asset tag (16 bytes)


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


class AssetPackageConfig:
    CFG_SECTION_NAME = "CMPU-ASSET-CFG"

    def __init__(self):
        self._asset_type = None
        self._unique_data = None
        self._key_filename = None
        self._keypwd_filename = ""
        self._asset_filename = None
        self._pkg_filename = None

    @property
    def section_name(self):
        return self.CFG_SECTION_NAME

    @property
    def asset_type(self):
        return self._asset_type

    @asset_type.setter
    def asset_type(self, value):
        if isinstance(value, str) is False:
            raise TypeError("Config parameter asset-type must be a string")
        elif value not in ["kpicv", "kceicv"]:  # asset_type_prov or asset_type_enc
            raise ValueError("Config parameter asset-type has invalid input value")
        else:
            self._asset_type = value

    @property
    def unique_data(self):
        return self._unique_data

    @unique_data.setter
    def unique_data(self, value):
        if isinstance(value, str) is False:
            raise TypeError("Config parameter unique-data must be a string")
        elif value == "":
            raise ValueError("Config parameter unique-data cannot be an empty string!")
        else:
            self._unique_data = value

    @property
    def key_filename(self):
        return self._key_filename

    @key_filename.setter
    def key_filename(self, value):
        if value == "":
            raise ValueError("Config parameter key-filename cannot be an empty string!")
        elif isinstance(value, str) is False:
            raise TypeError("Config parameter key-filename must be a string")
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
    def asset_filename(self):
        return self._asset_filename

    @asset_filename.setter
    def asset_filename(self, value):
        if value == "":
            raise ValueError("Config parameter asset-filename cannot be an empty string!")
        elif isinstance(value, str) is False:
            raise TypeError("Config parameter asset-filename must be a string")
        else:
            self._asset_filename = value

    @property
    def pkg_filename(self):
        return self._pkg_filename

    @pkg_filename.setter
    def pkg_filename(self, value):
        if isinstance(value, str) is False:
            raise TypeError("Config parameter pkg-filename must be a string")
        elif value == "":
            raise ValueError("Config parameter pkg-filename cannot be an empty string!")
        else:
            self._pkg_filename = value


class AssetPackageConfigParser:

    def __init__(self, config_filename):
        self.config_filename = config_filename
        self.config = configparser.ConfigParser()
        self.logger = logging.getLogger()
        self._config_holder = AssetPackageConfig()

    def get_config(self):
        return self._config_holder

    def parse_config(self):
        self.logger.info("Parsing config file: " + self.config_filename)
        self.config.read(self.config_filename)

        if not self.config.has_section(self._config_holder.section_name):
            self.logger.warning("section [" + self._config_holder.section_name + "] wasn't found in cfg file")
            return False

        if not self.config.has_option(self._config_holder.section_name, 'asset-type'):
            self.logger.warning("asset-type not found")
            return False
        else:
            self._config_holder.asset_type = self.config.get(self._config_holder.section_name, 'asset-type')

        if not self.config.has_option(self._config_holder.section_name, 'unique-data'):
            self.logger.warning("unique-data not found")
            return False
        else:
            self._config_holder.unique_data = self.config.get(self._config_holder.section_name, 'unique-data')

        if not self.config.has_option(self._config_holder.section_name, 'key-filename'):
            self.logger.warning("key-filename not found")
            return False
        else:
            self._config_holder.key_filename = self.config.get(self._config_holder.section_name, 'key-filename')

        if self.config.has_option(self._config_holder.section_name, 'keypwd-filename'):
            self._config_holder.keypwd_filename = self.config.get(self._config_holder.section_name, 'keypwd-filename')

        if not self.config.has_option(self._config_holder.section_name, 'asset-filename'):
            self.logger.warning("asset-filename not found")
            return False
        else:
            self._config_holder.asset_filename = self.config.get(self._config_holder.section_name, 'asset-filename')

        if not self.config.has_option(self._config_holder.section_name, 'pkg-filename'):
            self.logger.warning("pkg-filename not found")
            return False
        else:
            self._config_holder.pkg_filename = self.config.get(self._config_holder.section_name, 'pkg-filename')

        return True


class AssetPackager:
    ASSET_SIZE = 16
    USER_DATA_SIZE = 16
    KRTL_SIZE = 16
    ASSET_BLOCK_SIZE = 16

    PROD_ASSET_PROV_TOKEN = 0x50726F64
    PROD_ASSET_PROV_VERSION = 0x10000
    PROD_ASSET_RESERVED1_VAL = 0x52657631
    PROD_ASSET_RESERVED2_VAL = 0x52657632
    PROD_ASSET_NONCE_SIZE = 12
    PROD_ICV_KEY_TMP_LABEL = "KEY ICV"
    PROD_ICV_ENC_CONTEXT = "EICV"
    PROD_ICV_PROV_CONTEXT = "PICV"

    def __init__(self, key_cfg):
        self.config = key_cfg
        self.logger = logging.getLogger()

    def generate_package(self):
        with open(self.config.asset_filename, "rb") as asset_file:
            asset_data = asset_file.read()
        asset_data_size = len(asset_data)
        if asset_data_size != self.ASSET_SIZE:
            self.logger.warning("Invalid asset size: " + str(asset_data_size))
            sys.exit(-1)

        with open(self.config.unique_data, "rb") as userdata_file:
            user_data = userdata_file.read()
        user_data_size = len(user_data)
        if user_data_size != self.USER_DATA_SIZE:
            self.logger.warning("Invalid unique data size: " + str(user_data_size))
            sys.exit(-1)

        with open(self.config.key_filename, "rb") as key_file:
            key_data = key_file.read()
        key_data_size = len(key_data)
        if key_data_size != self.KRTL_SIZE + self.ASSET_BLOCK_SIZE:
            self.logger.warning("Invalid key size: " + str(key_data_size))
            sys.exit(-1)

        self.logger.info("**** Generate Production Asset package ****")
        # build package header
        nonce = os.urandom(self.PROD_ASSET_NONCE_SIZE)
        asset_package = (struct.pack('<I', self.PROD_ASSET_PROV_TOKEN)
                         + struct.pack('<I', self.PROD_ASSET_PROV_VERSION)
                         + struct.pack('<I', asset_data_size)
                         + struct.pack('<I', self.PROD_ASSET_RESERVED1_VAL)
                         + struct.pack('<I', self.PROD_ASSET_RESERVED2_VAL))
        # decrypt Krtl
        decrypted_krtl_key = cryptolayer.Common.decrypt_asset_with_aes_cbc(key_data,
                                                                           self.config.keypwd_filename)
        if self.config.asset_type == "kceicv":
            key_prov_context = self.PROD_ICV_ENC_CONTEXT
        else:
            key_prov_context = self.PROD_ICV_PROV_CONTEXT
        # calculate Ktmp = cmac(Krtl, 0x01 || ICV/OEM_label  || 0x0 || user context || 0x80)
        input_data = (struct.pack('B', 0x01)
                      + self.PROD_ICV_KEY_TMP_LABEL.encode('utf-8')
                      + struct.pack('B', 0)
                      + user_data
                      + struct.pack('B', 0x80))  # outkeysize in bits
        key_tmp = cryptolayer.AesCrypto.calc_aes_cmac(input_data, decrypted_krtl_key)

        # calculate Kprov= cmac(Ktmp, 0x01 || "P"  || 0x0 || key_prov_context? || 0x80)
        input_data = (struct.pack('B', 0x01)
                      + struct.pack('B', 0x50)
                      + struct.pack('B', 0)
                      + key_prov_context.encode('utf-8')
                      + struct.pack('B', 0x80))  # outkeysize in bits
        prov_key = cryptolayer.AesCrypto.calc_aes_cmac(input_data, key_tmp)

        # encrypt and authenticate the asset
        encrypted_data_and_tag = cryptolayer.AesCrypto.encrypt_aes_ccm(prov_key, nonce, asset_package, asset_data)
        # attach encrypted data to asset blob and nonce
        asset_package += nonce
        asset_package += encrypted_data_and_tag
        # write asset blob to output file
        with open(self.config.pkg_filename, "wb") as encrypted_outfile:
            encrypted_outfile.write(asset_package)


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
    config_parser = AssetPackageConfigParser(the_argument_parser.cfg_filename)
    if config_parser.parse_config() is False:
        logger.critical("Config file parsing is not successful")
        sys.exit(-1)
    # create secure asset package
    asset_provisioner = AssetPackager(config_parser.get_config())
    asset_provisioner.generate_package()
    logger.info("**** Asset package generation has been completed successfully ****")
