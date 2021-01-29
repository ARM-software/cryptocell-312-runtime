#!/usr/bin/env python3
#
# Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
#

####################################################################
# Filename - cert_dbg_enabler_util.py
# Description - This utility builds enabler debug certificate package
#                key certificate, if exists
#                token, version, length, flags (hbk,lcs, isRma)
#                certificate PubKey (pub key + Np)
#                debug Mask(4 words)
#                debug lock(4 words)
#                sha256 of devPubKey
#                certSign
####################################################################

import optparse
import configparser
import sys
import os
import logging
sys.path.append(os.path.join(sys.path[0], "..", ".."))

from common import loggerinitializer
from cc3x_boot_cert.common_cert_lib.enablercertificateconfig import EnablerDebugCertificateConfig
from cc3x_boot_cert.common_cert_lib.enablerdebugarmcertificate import EnablerDebugArmCertificate


# Util's log file
LOG_FILENAME = "sb_dbg1_cert.log"

# find proj.cfg
if "proj.cfg" in os.listdir(sys.path[0]):
    PROJ_CONFIG_PATH = os.path.join(sys.path[0], "proj.cfg")
elif "proj.cfg" in os.listdir(sys.path[-1]):
    PROJ_CONFIG_PATH = os.path.join(sys.path[-1], "proj.cfg")
else:
    PROJ_CONFIG_PATH = os.path.join(os.getcwd(), "proj.cfg")


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


class EnablerDebugCertificateCreator:
    def __init__(self, enabler_dbg_cfg, certificate_version):
        self.config = enabler_dbg_cfg
        self.logger = logging.getLogger()
        self.cert_version = certificate_version
        self._certificate = None

    def create_certificate(self):
        self.logger.info("**** Generate debug certificate ****")

        serialized_cert_data = b''
        if self.config.key_cert_pkg is not None and self.config.key_cert_pkg != "":
            with open(self.config.key_cert_pkg, "rb") as key_cert_input_file:
                key_certificate_data = key_cert_input_file.read()
                serialized_cert_data += key_certificate_data

        self._certificate = EnablerDebugArmCertificate(self.config, self.cert_version)
        serialized_cert_data += self._certificate.certificate_data

        with open(self.config.cert_pkg, "wb") as bin_output_file:
            bin_output_file.write(serialized_cert_data)


if __name__ == "__main__":
    if not (sys.version_info.major == 3 and sys.version_info.minor >= 5):
        sys.exit("The script requires Python3.5 or later!")
    # parse arguments
    the_argument_parser = ArgumentParser()
    the_argument_parser.parse_arguments()
    # get logging up and running
    logger_config = loggerinitializer.LoggerInitializer(the_argument_parser.log_filename)
    logger = logging.getLogger()
    # Get the project configuration values
    project_config = configparser.ConfigParser()
    with open(PROJ_CONFIG_PATH, 'r') as project_config_file:
        config_string = '[PROJ-CFG]\n' + project_config_file.read()
    project_config.read_string(config_string)
    cert_version = [project_config.getint("PROJ-CFG", "CERT_VERSION_MAJOR"),
                    project_config.getint("PROJ-CFG", "CERT_VERSION_MINOR")]
    # get util configuration parameters
    enabler_certificate_config = EnablerDebugCertificateConfig(the_argument_parser.cfg_filename)
    # create certificate
    cert_creator = EnablerDebugCertificateCreator(enabler_certificate_config, cert_version)
    cert_creator.create_certificate()
    logger.info("**** Certificate file creation has been completed successfully ****")
