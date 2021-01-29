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
LOG_FILENAME = "asset_prov.log"

# This utility builds asset provisioning BLOB package:
# the package format is:
#                       token, version, asset length, user data (20 bytes)
#                       nonce(12 bytes)
#                       encrypted asset (up to 4096 bytes - multiple of 16 bytes)
#                       asset tag (16 bytes)


class ArgumentParser:
    def __init__(self):
        self.cfg_filename = None
        self.log_filename = LOG_FILENAME
        self.parser = optparse.OptionParser(usage="usage: %prog <cfg_file> [<log_filename>]",
                                            description="%prog builds asset blob. Its configuration must be given in "
                                                        "<cfg_file>. Optionally, the default log filename can be "
                                                        "changed with parameter <log_filename>.")

    def parse_arguments(self):
        (options, args) = self.parser.parse_args()
        if len(args) > 2 or len(args) < 1:
            self.parser.error("incorrect number of positional arguments")
        elif len(args) == 2:
            self.log_filename = args[1]
        self.cfg_filename = args[0]


class AssetProvisioningConfig:
    CFG_SECTION_NAME = "ASSET-PROV-CFG"

    def __init__(self):
        self._key_filename = None
        self._keypwd_filename = ""
        self._asset_id = None
        self._asset_filename = None
        self._asset_pkg = "asset_pkg.bin"

    @property
    def section_name(self):
        return self.CFG_SECTION_NAME

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
    def asset_id(self):
        return self._asset_id

    @asset_id.setter
    def asset_id(self, value):
        if isinstance(value, int) is False:
            raise TypeError("Config parameter asset-id must be an integer")
        elif not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("invalid input value for config parameter asset-id")
        else:
            self._asset_id = value

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
    def asset_pkg(self):
        return self._asset_pkg

    @asset_pkg.setter
    def asset_pkg(self, value):
        if isinstance(value, str) is False:
            raise TypeError("Config parameter asset-pkg must be a string")
        elif value != "":
            self._asset_pkg = value


class AssetProvisioningConfigParser:

    def __init__(self, config_filename):
        self.config_filename = config_filename
        self.config = configparser.ConfigParser()
        self.logger = logging.getLogger()
        self._config_holder = AssetProvisioningConfig()

    def get_config(self):
        return self._config_holder

    def parse_config(self):
        self.logger.info("Parsing config file: " + self.config_filename)
        self.config.read(self.config_filename)

        if not self.config.has_section(self._config_holder.section_name):
            self.logger.warning("section [" + self._config_holder.section_name + "] wasn't found in cfg file")
            return False

        if not self.config.has_option(self._config_holder.section_name, 'key-filename'):
            self.logger.warning("key-filename not found")
            return False
        else:
            self._config_holder.key_filename = self.config.get(self._config_holder.section_name, 'key-filename')

        if self.config.has_option(self._config_holder.section_name, 'keypwd-filename'):
            self._config_holder.keypwd_filename = self.config.get(self._config_holder.section_name, 'keypwd-filename')

        if not self.config.has_option(self._config_holder.section_name, 'asset-id'):
            self.logger.warning("asset-id not found")
            return False
        else:
            self._config_holder.asset_id = int(self.config.get(self._config_holder.section_name, 'asset-id'), 16)

        if not self.config.has_option(self._config_holder.section_name, 'asset-filename'):
            self.logger.warning("asset-filename not found")
            return False
        else:
            self._config_holder.asset_filename = self.config.get(self._config_holder.section_name, 'asset-filename')

        if not self.config.has_option(self._config_holder.section_name, 'asset-pkg'):
            self.logger.warning("asset-pkg not found")
            return False
        else:
            self._config_holder.asset_pkg = self.config.get(self._config_holder.section_name, 'asset-pkg')

        return True


class AssetProvisioner:
    CC_ASSET_PROV_MAX_ASSET_SIZE = 4096
    ASSET_BLOCK_SIZE = 16
    KPICV_KEY_SIZE = 16

    CC_ASSET_PROV_TOKEN = 0x41736574
    CC_ASSET_PROV_VERSION = 0x10000
    CC_ASSET_PROV_NONCE_SIZE = 12
    CC_ASSET_PROV_RESERVED_SIZE = 8
    CC_32BIT_WORD_SIZE = 4
    CC_ASSET_PROV_RESERVED_WORD_SIZE = CC_ASSET_PROV_RESERVED_SIZE // CC_32BIT_WORD_SIZE
    CC_ASSET_PROV_TAG_SIZE = 16

    def __init__(self, key_cfg):
        self.config = key_cfg
        self.logger = logging.getLogger()

    def generate_package(self):
        with open(self.config.asset_filename, "rb") as asset_file:
            asset_data = asset_file.read()
        asset_data_size = len(asset_data)
        if asset_data_size == 0 or \
                asset_data_size > self.CC_ASSET_PROV_MAX_ASSET_SIZE or asset_data_size % self.ASSET_BLOCK_SIZE != 0:
            self.logger.warning("Invalid asset size: " + str(asset_data_size))
            sys.exit(-1)

        with open(self.config.key_filename, "rb") as key_file:
            key_data = key_file.read()
        key_data_size = len(key_data)
        if key_data_size != self.KPICV_KEY_SIZE + self.ASSET_BLOCK_SIZE:
            self.logger.warning("Invalid key size: " + str(key_data_size))
            sys.exit(-1)

        self.logger.info("**** Generate Asset BLOB ****")
        # build blob header
        nonce = os.urandom(self.CC_ASSET_PROV_NONCE_SIZE)

        asset_blob = (struct.pack('<I', self.CC_ASSET_PROV_TOKEN)
                      + struct.pack('<I', self.CC_ASSET_PROV_VERSION)
                      + struct.pack('<I', asset_data_size)
                      + struct.pack('<I', 0) * self.CC_ASSET_PROV_RESERVED_WORD_SIZE)

        # decrypt Kpicv/Kcp
        decrypted_key = cryptolayer.Common.decrypt_asset_with_aes_cbc(key_data, self.config.keypwd_filename)

        # Calculate Kprov = cmac(Kpicv, 0x01 || 0x50 || 0x00 || asset id || 0x80)
        input_data = (struct.pack('B', 0x01)
                      + struct.pack('B', 0x50)
                      + struct.pack('B', 0)
                      + struct.pack('<I', self.config.asset_id)
                      + struct.pack('B', 0x80))  # outkeysize in bits

        prov_key = cryptolayer.AesCrypto.calc_aes_cmac(input_data, decrypted_key)

        # encrypt and authenticate the asset
        encrypted_data_and_tag = cryptolayer.AesCrypto.encrypt_aes_ccm(prov_key, nonce, asset_blob, asset_data)
        # attach encrypted data to asset blob and nonce
        asset_blob += nonce
        asset_blob += encrypted_data_and_tag
        # write asset blob to output file
        with open(self.config.asset_pkg, "wb") as encrypted_outfile:
            encrypted_outfile.write(asset_blob)


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
    config_parser = AssetProvisioningConfigParser(the_argument_parser.cfg_filename)
    if config_parser.parse_config() is False:
        logger.critical("Config file parsing is not successful")
        sys.exit(-1)
    # create secure asset package
    asset_provisioner = AssetProvisioner(config_parser.get_config())
    asset_provisioner.generate_package()
    logger.info("**** Asset BLOB generation has been completed successfully ****")
