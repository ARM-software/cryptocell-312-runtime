#!/usr/bin/env python3
#
# Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
#

# This utility builds developer debug certificate package:
#       enabler certificate should be located before the developer certificate
#       x509 header containing: version of certificate
#                               serial number
#                               certificate algorithm identifier of the issuer signature
#                               Certificate Issuer name
#                               Validity period
#                               Subject name
#       certificate public key: public key algorithm ID
#                               public key - 3072 bits
#       certificate extensions: ARM certificate header: token,
#                                                       version,
#                                                       length,
#                                                       flags: reserved word
#                               Barret Tag of public key (Np)
#                               Developer certificate body: debug mask value - 128 bit
#                                                           SoC-ID - 128 bit
#       certificate signature: certificate algorithm identifier of the issuer signature
#                              signature of (x509 header + certificate public key + certificate extensions) - 3072 bits
#

import optparse
import configparser
import sys
import os
import logging

sys.path.append(os.path.join(sys.path[0], "..", ".."))
from common import loggerinitializer
from cc3x_boot_cert.common_cert_lib.developercertificateconfig import DeveloperDebugCertificateConfig
from cc3x_boot_cert.common_cert_lib import x509certificates

# Util's log file
LOG_FILENAME = "sb_dbg2_cert.log"

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


class X509DeveloperDebugCertificateCreator:
    def __init__(self, developer_dbg_cfg, certificate_version):
        self.developer_cert_config = developer_dbg_cfg
        self.logger = logging.getLogger()
        self.cert_version = certificate_version
        self._certificate = None

    def create_certificate(self):
        self.logger.info("**** Creating X509 developer debug certificate ****")

        certificate = x509certificates.DeveloperDebugX509Certificate(self.developer_cert_config,
                                                                     self.cert_version)

        self.logger.info("Write the certificate to cert-pkg output file as a DER encoded binary")
        with open(self.developer_cert_config.cert_pkg, "wb") as bin_output_file:
            bin_output_file.write(certificate.certificate_data)


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
    developer_certificate_config = DeveloperDebugCertificateConfig(the_argument_parser.cfg_filename)
    # create certificate
    cert_creator = X509DeveloperDebugCertificateCreator(developer_certificate_config, cert_version)
    cert_creator.create_certificate()
    logger.info("**** Certificate file creation has been completed successfully ****")
