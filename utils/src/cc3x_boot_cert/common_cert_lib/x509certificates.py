# Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
#

import abc
from enum import IntEnum
import datetime
import os
import struct
import logging

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.primitives import hashes

from cc3x_boot_cert.common_cert_lib import x509_signature_util
from cc3x_boot_cert.common_cert_lib.contentarmcertificate import ContentArmCertificateHeader, ContentArmCertificateBody
from cc3x_boot_cert.common_cert_lib.keyarmcertificate import KeyArmCertificateHeader
from cc3x_boot_cert.common_cert_lib.developerdebugarmcertificate import DeveloperDebugArmCertificateHeader
from cc3x_boot_cert.common_cert_lib.enablerdebugarmcertificate import EnablerDebugArmCertificateHeader
from common import cryptolayer
from common import global_defines


class X509CertTypeOid(IntEnum):
    KEY = 1
    CONTENT = 2
    ENABLER_DEBUG = 3
    DEVELOPER_DEBUG = 4


class X509CertExtensionIdOid(IntEnum):
    PROPRIETARY_HEADER = 1
    PUB_KEY_NP_TAG = 2
    KEY_CERT_MAIN_VAL = 3
    CONTENT_CERT_MAIN_VAL = 4
    ENABLER_CERT_MAIN_VAL = 5
    DEVELOPER_CERT_MAIN_VAL = 6


class X509Certificate(abc.ABC):
    X509_CERT_OID_PREFIX = "2.20"

    def __init__(self, subject_name):
        self.cert_builder = x509.CertificateBuilder()
        # setting serial number
        # |-> 4 bytes to keep backwards compatibility
        # |-> ASN.1 integers are always signed -> need to make sure it stays 4 bytes (purpose of shifting)
        self.cert_builder = self.cert_builder.serial_number(int.from_bytes(os.urandom(4), "big") >> 1)
        self.cert_builder = self.cert_builder.not_valid_before(datetime.datetime.utcnow())
        # setting expiration date: ~100 years
        self.cert_builder = self.cert_builder.not_valid_after(datetime.datetime.utcnow()
                                                              + datetime.timedelta(seconds=0xfffffffe))
        # set subject name - depends on certificate type
        self.cert_builder = self.cert_builder.subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject_name)
        ]))
        # set issuer name
        self.cert_builder = self.cert_builder.issuer_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ARM")
        ]))

    def replace_signature_with_rsassa_pss(self, certificate_tbs_data, cert_private_key):
        rsassa_pss_signature_id_encoded = x509_signature_util.encode_rsassa_psa_signature_id()
        replaced_encoded_tbs_data = x509_signature_util.replace_signature_id_in_tbs_certificate(
            certificate_tbs_data,
            rsassa_pss_signature_id_encoded)
        reencoded_certificate = replaced_encoded_tbs_data + rsassa_pss_signature_id_encoded
        rsa_pss_signature = cryptolayer.Common.rsa_sign_with_private_key(replaced_encoded_tbs_data,
                                                                         cert_private_key)
        reencoded_certificate = x509_signature_util.encode_signature_and_create_final_structure(
            reencoded_certificate,
            rsa_pss_signature)
        return reencoded_certificate

    @property
    @abc.abstractmethod
    def certificate_data(self):
        pass


class KeyX509Certificate(X509Certificate):
    def __init__(self, cert_version, hbk_id, signer_keypair_filename, signer_keypair_passphrase_filename,
                 next_cert_pubkey_filename, sw_version):
        super().__init__("KeyCert")
        self.logger = logging.getLogger()
        self._cert_version = cert_version
        self._hbk_id = hbk_id
        # loading private key and its derived parameters
        self.cert_private_key = cryptolayer.RsaCrypto.load_rsa_pem_key(signer_keypair_filename,
                                                                       True,
                                                                       signer_keypair_passphrase_filename)
        self.cert_public_key = self.cert_private_key.public_key()
        np_tag = cryptolayer.RsaCrypto.calculate_np_from_n(
            cryptolayer.RsaCrypto.get_n_from_rsa_pem_public_key(self.cert_public_key))

        # add Arm proprietary cert header as extension
        arm_header_extension = KeyArmCertificateHeader(self._cert_version, self._hbk_id).serialize_to_bytes()
        arm_header_extension_oid = ObjectIdentifier(".".join([self.X509_CERT_OID_PREFIX,
                                                              str(X509CertTypeOid.KEY.value),
                                                              str(X509CertExtensionIdOid.PROPRIETARY_HEADER.value)]))
        self.cert_builder = self.cert_builder.add_extension(
            x509.UnrecognizedExtension(arm_header_extension_oid, arm_header_extension), critical=True)

        # add Barret tag of Public key (Np) as extension
        np_tag_in_bytes = np_tag.to_bytes(cryptolayer.RsaCrypto.NP_SIZE_IN_BYTES, 'big')
        np_tag_extension_oid = ObjectIdentifier(".".join([self.X509_CERT_OID_PREFIX,
                                                          str(X509CertTypeOid.KEY.value),
                                                          str(X509CertExtensionIdOid.PUB_KEY_NP_TAG.value)]))
        self.cert_builder = self.cert_builder.add_extension(
            x509.UnrecognizedExtension(np_tag_extension_oid, np_tag_in_bytes), critical=True)

        # add Arm proprietary key cert body as extension
        self.next_cert_pubkey = cryptolayer.Common.get_hashed_n_and_np_from_public_key(next_cert_pubkey_filename)
        arm_body_extension = struct.pack('<I', sw_version) + self.next_cert_pubkey
        arm_body_extension_oid = ObjectIdentifier(".".join([self.X509_CERT_OID_PREFIX,
                                                            str(X509CertTypeOid.KEY.value),
                                                            str(X509CertExtensionIdOid.KEY_CERT_MAIN_VAL.value)]))
        self.cert_builder = self.cert_builder.add_extension(
            x509.UnrecognizedExtension(arm_body_extension_oid, arm_body_extension), critical=True)

        # set public key
        self.cert_builder = self.cert_builder.public_key(self.cert_public_key)
        # sign certificate with cryptolayer's signing algorithm: sha256WithRSAEncryption
        self.certificate = self.cert_builder.sign(private_key=self.cert_private_key, algorithm=hashes.SHA256())
        # sanity check
        if not isinstance(self.certificate, x509.Certificate):
            self.logger.error("type of generated certificate is not x509.Certificate")

        # replace signature with RSASSA_PSS
        self._certificate_der_encoded = self.replace_signature_with_rsassa_pss(self.certificate.tbs_certificate_bytes,
                                                                               self.cert_private_key)

    @property
    def certificate_data(self):
        return self._certificate_der_encoded


class ContentX509Certificate(X509Certificate):
    def __init__(self, cert_version, content_cfg):
        super().__init__("CntCert")
        self.logger = logging.getLogger()
        self._cert_version = cert_version
        self.content_cert_config = content_cfg
        # loading private key and its derived parameters
        self.cert_private_key = cryptolayer.RsaCrypto.load_rsa_pem_key(self.content_cert_config.cert_keypair,
                                                                       True,
                                                                       self.content_cert_config.cert_keypair_pwd)
        self.cert_public_key = self.cert_private_key.public_key()
        np_tag = cryptolayer.RsaCrypto.calculate_np_from_n(
            cryptolayer.RsaCrypto.get_n_from_rsa_pem_public_key(self.cert_public_key))

        # assembling arm proprietary certificate body and header
        arm_content_cert_body = ContentArmCertificateBody(self.content_cert_config.nvcounter_val,
                                                          self.content_cert_config.cert_keypair,
                                                          self.content_cert_config.cert_keypair_pwd,
                                                          self.content_cert_config.aes_ce_id,
                                                          self.content_cert_config.images_table,
                                                          self.content_cert_config.load_verify_scheme,
                                                          self.content_cert_config.aes_enc_key,
                                                          self.content_cert_config.crypto_type)
        num_of_comps = arm_content_cert_body.num_images
        arm_content_cert_header = ContentArmCertificateHeader(self._cert_version,
                                                              self.content_cert_config.aes_ce_id,
                                                              self.content_cert_config.load_verify_scheme,
                                                              self.content_cert_config.crypto_type,
                                                              num_of_comps)

        # add Arm proprietary cert header as extension
        arm_header_extension = arm_content_cert_header.serialize_to_bytes()
        arm_header_extension_oid = ObjectIdentifier(".".join([self.X509_CERT_OID_PREFIX,
                                                              str(X509CertTypeOid.CONTENT.value),
                                                              str(X509CertExtensionIdOid.PROPRIETARY_HEADER.value)]))
        self.cert_builder = self.cert_builder.add_extension(
            x509.UnrecognizedExtension(arm_header_extension_oid, arm_header_extension), critical=True)

        # add Barret tag of Public key (Np) as extension
        np_tag_in_bytes = np_tag.to_bytes(cryptolayer.RsaCrypto.NP_SIZE_IN_BYTES, 'big')
        np_tag_extension_oid = ObjectIdentifier(".".join([self.X509_CERT_OID_PREFIX,
                                                          str(X509CertTypeOid.CONTENT.value),
                                                          str(X509CertExtensionIdOid.PUB_KEY_NP_TAG.value)]))
        self.cert_builder = self.cert_builder.add_extension(
            x509.UnrecognizedExtension(np_tag_extension_oid, np_tag_in_bytes), critical=True)

        # add Arm proprietary content cert body as extension
        arm_body_extension = arm_content_cert_body.x509_body_extension_data
        arm_body_extension_oid = ObjectIdentifier(".".join([self.X509_CERT_OID_PREFIX,
                                                            str(X509CertTypeOid.CONTENT.value),
                                                            str(X509CertExtensionIdOid.CONTENT_CERT_MAIN_VAL.value)]))
        self.cert_builder = self.cert_builder.add_extension(
            x509.UnrecognizedExtension(arm_body_extension_oid, arm_body_extension), critical=True)

        # set public key
        self.cert_builder = self.cert_builder.public_key(self.cert_public_key)
        # sign certificate with cryptolayer's signing algorithm: sha256WithRSAEncryption
        self.certificate = self.cert_builder.sign(private_key=self.cert_private_key, algorithm=hashes.SHA256())
        # sanity check
        if not isinstance(self.certificate, x509.Certificate):
            self.logger.error("type of generated certificate is not x509.Certificate")

        # replace signature with RSASSA_PSS
        self._certificate_der_encoded = self.replace_signature_with_rsassa_pss(self.certificate.tbs_certificate_bytes,
                                                                               self.cert_private_key)
        # append with none-signed info and align certificate to 4bytes
        remainder_bytes = len(self._certificate_der_encoded) % 4
        if remainder_bytes != 0:
            appended_bytes = 4 - remainder_bytes
        else:
            appended_bytes = 0
        self._certificate_der_encoded += bytes(appended_bytes)
        self._certificate_der_encoded += arm_content_cert_body.none_signed_info_serialized

    @property
    def certificate_data(self):
        return self._certificate_der_encoded


class EnablerDebugX509Certificate(X509Certificate):
    def __init__(self, enabler_dbg_cfg, cert_version):
        super().__init__("EnablerDbg")
        self.logger = logging.getLogger()
        self._cert_version = cert_version
        self.enabler_cert_config = enabler_dbg_cfg
        # loading private key and its derived parameters
        self.cert_private_key = cryptolayer.RsaCrypto.load_rsa_pem_key(self.enabler_cert_config.cert_keypair,
                                                                       True,
                                                                       self.enabler_cert_config.cert_keypair_pwd)
        self.cert_public_key = self.cert_private_key.public_key()
        np_tag = cryptolayer.RsaCrypto.calculate_np_from_n(
            cryptolayer.RsaCrypto.get_n_from_rsa_pem_public_key(self.cert_public_key))

        # add Arm proprietary cert header as extension
        arm_header_extension = EnablerDebugArmCertificateHeader(self._cert_version,
                                                                self.enabler_cert_config.rma_mode,
                                                                self.enabler_cert_config.hbk_id,
                                                                self.enabler_cert_config.lcs).serialize_to_bytes()
        arm_header_extension_oid = ObjectIdentifier(".".join([self.X509_CERT_OID_PREFIX,
                                                              str(X509CertTypeOid.ENABLER_DEBUG.value),
                                                              str(X509CertExtensionIdOid.PROPRIETARY_HEADER.value)]))
        self.cert_builder = self.cert_builder.add_extension(
            x509.UnrecognizedExtension(arm_header_extension_oid, arm_header_extension), critical=True)

        # add Barret tag of Public key (Np) as extension
        np_tag_in_bytes = np_tag.to_bytes(cryptolayer.RsaCrypto.NP_SIZE_IN_BYTES, 'big')
        np_tag_extension_oid = ObjectIdentifier(".".join([self.X509_CERT_OID_PREFIX,
                                                          str(X509CertTypeOid.ENABLER_DEBUG.value),
                                                          str(X509CertExtensionIdOid.PUB_KEY_NP_TAG.value)]))
        self.cert_builder = self.cert_builder.add_extension(
            x509.UnrecognizedExtension(np_tag_extension_oid, np_tag_in_bytes), critical=True)

        # add Arm proprietary enabler cert body as extension
        self.next_cert_pubkey = cryptolayer.Common.get_hashed_n_and_np_from_public_key(
            self.enabler_cert_config.next_cert_pubkey)
        arm_body_extension = (b''.join([struct.pack('<I', i) for i in self.enabler_cert_config.debug_masks])
                              + b''.join([struct.pack('<I', i) for i in self.enabler_cert_config.debug_locks])
                              + self.next_cert_pubkey)
        arm_body_extension_oid = ObjectIdentifier(".".join([self.X509_CERT_OID_PREFIX,
                                                            str(X509CertTypeOid.ENABLER_DEBUG.value),
                                                            str(X509CertExtensionIdOid.ENABLER_CERT_MAIN_VAL.value)]))
        self.cert_builder = self.cert_builder.add_extension(
            x509.UnrecognizedExtension(arm_body_extension_oid, arm_body_extension), critical=True)

        # set public key
        self.cert_builder = self.cert_builder.public_key(self.cert_public_key)
        # sign certificate with cryptolayer's signing algorithm: sha256WithRSAEncryption
        self.certificate = self.cert_builder.sign(private_key=self.cert_private_key, algorithm=hashes.SHA256())
        # sanity check
        if not isinstance(self.certificate, x509.Certificate):
            self.logger.error("type of generated certificate is not x509.Certificate")

        # replace signature with RSASSA_PSS
        self._certificate_der_encoded = self.replace_signature_with_rsassa_pss(self.certificate.tbs_certificate_bytes,
                                                                               self.cert_private_key)

        # if key package exists it needs to be inserted at the beginning of the enabler certificate
        if self.enabler_cert_config.key_cert_pkg is not None and self.enabler_cert_config.key_cert_pkg != "":
            with open(self.enabler_cert_config.key_cert_pkg, "rb") as key_cert_input_file:
                key_certificate_data = key_cert_input_file.read()
            # align inserted data to 4bytes
            remainder_bytes = len(key_certificate_data) % 4
            if remainder_bytes != 0:
                appended_bytes = 4 - remainder_bytes
            else:
                appended_bytes = 0
            self._certificate_der_encoded = key_certificate_data + bytes(appended_bytes) + self._certificate_der_encoded

    @property
    def certificate_data(self):
        return self._certificate_der_encoded


class DeveloperDebugX509Certificate(X509Certificate):
    def __init__(self, developer_dbg_cfg, cert_version):
        super().__init__("DeveloperDbg")
        self.logger = logging.getLogger()
        self._cert_version = cert_version
        self.developer_cert_config = developer_dbg_cfg
        # loading private key and its derived parameters
        self.cert_private_key = cryptolayer.RsaCrypto.load_rsa_pem_key(self.developer_cert_config.cert_keypair,
                                                                       True,
                                                                       self.developer_cert_config.cert_keypair_pwd)
        self.cert_public_key = self.cert_private_key.public_key()
        np_tag = cryptolayer.RsaCrypto.calculate_np_from_n(
            cryptolayer.RsaCrypto.get_n_from_rsa_pem_public_key(self.cert_public_key))

        # add Arm proprietary cert header as extension
        arm_header_extension = DeveloperDebugArmCertificateHeader(self._cert_version).serialize_to_bytes()
        arm_header_extension_oid = ObjectIdentifier(".".join([self.X509_CERT_OID_PREFIX,
                                                              str(X509CertTypeOid.DEVELOPER_DEBUG.value),
                                                              str(X509CertExtensionIdOid.PROPRIETARY_HEADER.value)]))
        self.cert_builder = self.cert_builder.add_extension(
            x509.UnrecognizedExtension(arm_header_extension_oid, arm_header_extension), critical=True)

        # add Barret tag of Public key (Np) as extension
        np_tag_in_bytes = np_tag.to_bytes(cryptolayer.RsaCrypto.NP_SIZE_IN_BYTES, 'big')
        np_tag_extension_oid = ObjectIdentifier(".".join([self.X509_CERT_OID_PREFIX,
                                                          str(X509CertTypeOid.DEVELOPER_DEBUG.value),
                                                          str(X509CertExtensionIdOid.PUB_KEY_NP_TAG.value)]))
        self.cert_builder = self.cert_builder.add_extension(
            x509.UnrecognizedExtension(np_tag_extension_oid, np_tag_in_bytes), critical=True)

        # add Arm proprietary developer cert body as extension
        with open(self.developer_cert_config.soc_id, "rb") as soc_id_holder_file:
            soc_id = soc_id_holder_file.read()
            if len(soc_id) != global_defines.SOC_ID_SIZE_IN_BYTES:
                raise ValueError("Invalid SoC_ID size in input file " + self.developer_cert_config.soc_id)
        arm_body_extension = (b''.join([struct.pack('<I', i) for i in self.developer_cert_config.debug_masks])
                              + soc_id)
        arm_body_extension_oid = ObjectIdentifier(".".join([self.X509_CERT_OID_PREFIX,
                                                            str(X509CertTypeOid.DEVELOPER_DEBUG.value),
                                                            str(X509CertExtensionIdOid.DEVELOPER_CERT_MAIN_VAL.value)]))
        self.cert_builder = self.cert_builder.add_extension(
            x509.UnrecognizedExtension(arm_body_extension_oid, arm_body_extension), critical=True)

        # set public key
        self.cert_builder = self.cert_builder.public_key(self.cert_public_key)
        # sign certificate with cryptolayer's signing algorithm: sha256WithRSAEncryption
        self.certificate = self.cert_builder.sign(private_key=self.cert_private_key, algorithm=hashes.SHA256())
        # sanity check
        if not isinstance(self.certificate, x509.Certificate):
            self.logger.error("type of generated certificate is not x509.Certificate")

        # replace signature with RSASSA_PSS
        self._certificate_der_encoded = self.replace_signature_with_rsassa_pss(self.certificate.tbs_certificate_bytes,
                                                                               self.cert_private_key)

        # if enabler cert package exists it needs to be inserted at the beginning
        if self.developer_cert_config.enabler_cert_pkg is not None and self.developer_cert_config.enabler_cert_pkg != "":
            with open(self.developer_cert_config.enabler_cert_pkg, "rb") as enabler_cert_input_file:
                enabler_certificate_data = enabler_cert_input_file.read()
                # align inserted data to 4bytes
                remainder_bytes = len(enabler_certificate_data) % 4
                if remainder_bytes != 0:
                    appended_bytes = 4 - remainder_bytes
                else:
                    appended_bytes = 0
                self._certificate_der_encoded = (enabler_certificate_data
                                                 + bytes(appended_bytes)
                                                 + self._certificate_der_encoded)

    @property
    def certificate_data(self):
        return self._certificate_der_encoded
