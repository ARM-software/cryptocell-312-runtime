#!/usr/bin/env python3
#
# Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
#

import optparse
import sys
import os
import logging

sys.path.append(os.path.join(sys.path[0], ".."))

from common import loggerinitializer
from common import cryptolayer

# Util's log file
LOG_FILENAME = "key_gen_log.log"


class ArgumentParser:
    def __init__(self):
        self.private_key_filename = None
        self.private_key_pwd_filename = None
        self.public_key_filename = None
        self.log_filename = None
        self.parser = optparse.OptionParser(usage="usage: %prog <private_key_filename> [options]",
                                            description="%prog generates a PEM encoded RSA private key and writes it "
                                                        "to the file specified by parameter <private_key_filename>. "
                                                        "Optionally it can also generate the corresponding public key "
                                                        "to the file specified by option -k.")
        self.parser.add_option("-p", "--pass_file", dest="private_key_pwd_filename",
                               help="Filename containing the passphrase for creating the private key, "
                                    "in plaintext format. For security considerations, this parameter can be omitted, "
                                    "in which case this utility will prompt for direct input.")
        self.parser.add_option("-k", "--pubkey", dest="public_key_filename",
                               help="If given, the public key will be also extracted into the PEM file specified "
                                    "by this parameter")
        self.parser.add_option("-l", "--log", dest="log_filename", default=LOG_FILENAME,
                               metavar="FILE",
                               help="Writes event log to FILE [default: %default]")

    def parse_arguments(self):
        (options, args) = self.parser.parse_args()
        if len(args) != 1:
            self.parser.error("incorrect number of positional arguments, use option -h for help")
        self.private_key_filename = args[0]
        self.private_key_pwd_filename = options.private_key_pwd_filename
        self.public_key_filename = options.public_key_filename
        self.log_filename = options.log_filename


class KeyGenerator:
    def __init__(self, argument_parser):
        self.argument_parser = argument_parser

    def generate_key(self):
        key = cryptolayer.RsaCrypto.generate_rsa_pem_key(self.argument_parser.private_key_filename,
                                                         self.argument_parser.private_key_pwd_filename)
        if self.argument_parser.public_key_filename is not None:
            cryptolayer.RsaCrypto.extract_public_rsa_pem_key(key, self.argument_parser.public_key_filename)


if __name__ == "__main__":
    if not (sys.version_info.major == 3 and sys.version_info.minor >= 5):
        sys.exit("The script requires Python3.5 or later!")
    # parse arguments
    the_argument_parser = ArgumentParser()
    the_argument_parser.parse_arguments()
    # get logging up and running
    logger_config = loggerinitializer.LoggerInitializer(the_argument_parser.log_filename)
    logger = logging.getLogger()
    # perform main task
    generator = KeyGenerator(the_argument_parser)
    generator.generate_key()
    logger.info("Script completed successfully")
