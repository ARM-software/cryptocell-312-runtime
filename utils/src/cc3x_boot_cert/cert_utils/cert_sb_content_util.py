#!/usr/bin/env python3
#
# Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
#

# Content certificate structure is :
#       FIELD NAME                                                  SIZE (words)
#       ----------                                                  ------------
#       Header token                                                   1
#       version number                                                 1
#       size in words (offset to signature)                            1
#       Flags                                                          1
#       N Pub key                                                     96
#       Np                                                             5
#       active SW version                                              1
#       NONCE                                                          2
#       signed S/W records(hash + load address + max size + flag)    N * (8+3)
#       RSA Signature                                                 96
#       none-signed S/W records(storage address + actual size)       N * (2)
#

import optparse
import configparser
import sys
import os
import logging
sys.path.append(os.path.join(sys.path[0], "..", ".."))

from common import loggerinitializer
from common import global_defines
from cc3x_boot_cert.common_cert_lib.contentcertificateconfig import ContentCertificateConfig
from cc3x_boot_cert.common_cert_lib.contentarmcertificate import ContentArmCertificate

# Util's log file
LOG_FILENAME = "sb_content_cert.log"

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


class ContentCertificateGenerator:
    def __init__(self, content_cfg, certificate_version):
        self.config = content_cfg
        self.logger = logging.getLogger()
        self.cert_version = certificate_version
        self._certificate = None

    def create_certificate(self):
        self.logger.info("**** Creating Content Certificate ****")

        self._certificate = ContentArmCertificate(self.config, self.cert_version)
        serialized_cert_data = self._certificate.certificate_data

        with open(self.config.cert_pkg, "wb") as bin_output_file:
            bin_output_file.write(serialized_cert_data)

        hex_formatted_cert = ["0x%02x" % i for i in list(self._certificate.certificate_data)]
        txt_filename = self.config.cert_pkg[:-4] + '_' + global_defines.Cert_FileName + global_defines.Cert_FileExtTxt
        with open(txt_filename, "w") as txt_output_file:
            txt_output_file.write("char cert_bin_image[] = {\n")
            txt_content = "".join([item + ',\n' if ind % 4 == 3 else item + ','
                                   for ind, item in enumerate(hex_formatted_cert)])
            txt_output_file.write(txt_content)
            txt_output_file.write("}")


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
    content_certificate_config = ContentCertificateConfig(the_argument_parser.cfg_filename)
    # create certificate
    cert_creator = ContentCertificateGenerator(content_certificate_config, cert_version)
    cert_creator.create_certificate()
    logger.info("**** Certificate file creation has been completed successfully ****")
