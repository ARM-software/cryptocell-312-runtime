# Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
#

import configparser
import logging

from common import global_defines


class ConfigParsingError(Exception):
    """Raised when trying to load a misconfigured CFG file"""
    pass


class KeyCertificateConfig:
    CFG_SECTION_NAME = "KEY-CFG"

    def __init__(self, config_filename):
        """
        Parses the KEY-CFG key certificate cfg file.
        Raises ConfigParsingError when cfg has been written incorrectly.
        Raises TypeError or ValueError when a cfg value is incorrect on its own.

        :param str config_filename: name of cfg file to parse
        """
        self._config_filename = config_filename
        self._logger = logging.getLogger()
        self._parser = configparser.ConfigParser()

        self._cert_keypair = None
        self._cert_keypair_pwd = None
        self._hbk_id = None
        self._nvcounter_val = None
        self._next_cert_pubkey = None
        self._cert_pkg = None
        self._parse_config()

    @property
    def section_name(self):
        return self.CFG_SECTION_NAME

    @property
    def cert_keypair(self):
        return self._cert_keypair

    @cert_keypair.setter
    def cert_keypair(self, value):
        if value == "":
            raise ValueError("Config parameter cert-keypair cannot be an empty string!")
        elif isinstance(value, str) is False:
            raise TypeError("Config parameter cert-keypair must be a string")
        else:
            self._cert_keypair = value

    @property
    def cert_keypair_pwd(self):
        return self._cert_keypair_pwd

    @cert_keypair_pwd.setter
    def cert_keypair_pwd(self, value):
        if isinstance(value, str) is False:
            raise TypeError("Config parameter cert-keypair-pwd must be a string")
        else:
            self._cert_keypair_pwd = value

    @property
    def hbk_id(self):
        return self._hbk_id

    @hbk_id.setter
    def hbk_id(self, value):
        if isinstance(value, int) is False:
            raise TypeError("Config parameter hbk_id must be an integer")
        elif value not in [0, 1, 2]:
            raise ValueError("invalid input value for config parameter hbk_id")
        else:
            self._hbk_id = value

    @property
    def nvcounter_val(self):
        return self._nvcounter_val

    @nvcounter_val.setter
    def nvcounter_val(self, value):
        if isinstance(value, int) is False:
            raise TypeError("Config parameter nvcounter_val must be an integer")
        elif value not in range(global_defines.SW_REVOCATION_MAX_NUM_OF_BITS_HBK2 + 1):
            raise ValueError("invalid input value for config parameter nvcounter_val")
        else:
            self._nvcounter_val = value

    @property
    def next_cert_pubkey(self):
        return self._next_cert_pubkey

    @next_cert_pubkey.setter
    def next_cert_pubkey(self, value):
        if isinstance(value, str) is False:
            raise TypeError("Config parameter next_cert_pubkey must be a string")
        elif value == "":
            raise ValueError("Config parameter next_cert_pubkey cannot be an empty string!")
        else:
            self._next_cert_pubkey = value

    @property
    def cert_pkg(self):
        return self._cert_pkg

    @cert_pkg.setter
    def cert_pkg(self, value):
        if isinstance(value, str) is False:
            raise TypeError("Config parameter cert_pkg must be a string")
        elif value == "":
            raise ValueError("Config parameter cert_pkg cannot be an empty string!")
        else:
            self._cert_pkg = value

    def _parse_config(self):
        if self._logger is not None:
            self._logger.info("Parsing config file: " + self._config_filename)
        parsed_list = self._parser.read(self._config_filename)
        if len(parsed_list) == 1 and self._logger is not None:
            self._logger.info(
                "\n".join(["Parsed config items:"]
                          + [":\t".join([item[0], item[1]]) for item in self._parser.items(self.CFG_SECTION_NAME)])
            )
        else:
            message = "File " + self._config_filename + " could not be parsed. The file may not exist."
            if self._logger is not None:
                self._logger.error(message)
            raise ConfigParsingError(message)
        if not self._parser.has_section(self.section_name):
            message = "section [" + self.section_name + "] wasn't found in cfg file"
            if self._logger is not None:
                self._logger.error(message)
            raise ConfigParsingError(message)

        if not self._parser.has_option(self.section_name, 'cert-keypair'):
            message = "cert-keypair not found"
            if self._logger is not None:
                self._logger.error(message)
            raise ConfigParsingError(message)
        else:
            self.cert_keypair = self._parser.get(self.section_name, 'cert-keypair')

        if self._parser.has_option(self.section_name, 'cert-keypair-pwd'):  # used for testing
            self.cert_keypair_pwd = self._parser.get(self.section_name, 'cert-keypair-pwd')
        else:
            self.cert_keypair_pwd = ''

        if not self._parser.has_option(self.section_name, 'hbk-id'):
            message = "hbk-id not found"
            if self._logger is not None:
                self._logger.error(message)
            raise ConfigParsingError(message)
        else:
            self.hbk_id = self._parser.getint(self.section_name, 'hbk-id')

        if not self._parser.has_option(self.section_name, 'nvcounter-val'):
            message = "nvcounter-val not found"
            if self._logger is not None:
                self._logger.error(message)
            raise ConfigParsingError(message)
        else:
            self.nvcounter_val = self._parser.getint(self.section_name, 'nvcounter-val')
        # verify nvcounter_val according to HBK
        if self.hbk_id == 0:
            max_value_nvcounter = global_defines.SW_REVOCATION_MAX_NUM_OF_BITS_HBK0
        elif self.hbk_id == 1:
            max_value_nvcounter = global_defines.SW_REVOCATION_MAX_NUM_OF_BITS_HBK1
        else:
            max_value_nvcounter = global_defines.SW_REVOCATION_MAX_NUM_OF_BITS_HBK2
        if self.nvcounter_val > max_value_nvcounter:
            message = "Invalid nvcounter-val based on given hbk-id"
            if self._logger is not None:
                self._logger.error(message)
            raise ConfigParsingError(message)

        if not self._parser.has_option(self.section_name, 'next-cert-pubkey'):
            message = "no next-cert-pubkey parameter found"
            if self._logger is not None:
                self._logger.error(message)
            raise ConfigParsingError(message)
        else:
            self.next_cert_pubkey = self._parser.get(self.section_name, 'next-cert-pubkey')

        if not self._parser.has_option(self.section_name, 'cert-pkg'):
            message = "no cert-pkg parameter found"
            if self._logger is not None:
                self._logger.error(message)
            raise ConfigParsingError(message)
        else:
            self.cert_pkg = self._parser.get(self.section_name, 'cert-pkg')
