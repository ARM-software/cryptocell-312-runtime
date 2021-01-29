# Copyright (c) 2001-2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause OR Arm’s non-OSI source license
#

import asn1


def encode_rsassa_psa_signature_id():
    encoder = asn1.Encoder()
    encoder.start()
    # encode main signature id sequence
    encoder.enter(nr=asn1.Numbers.Sequence)

    encoder.write("1.2.840.113549.1.1.10", asn1.Numbers.ObjectIdentifier)  # encode rsaPSS algorithm id
    # encode sequenced second part
    encoder.enter(nr=asn1.Numbers.Sequence)

    # encode Context class: zero
    encoder.enter(nr=0, cls=asn1.Classes.Context)
    encoder.enter(nr=asn1.Numbers.Sequence)
    encoder.write("2.16.840.1.101.3.4.2.1", asn1.Numbers.ObjectIdentifier)  # encode sha-256 oid
    encoder.leave()
    encoder.leave()
    # encode Context class: one
    encoder.enter(nr=1, cls=asn1.Classes.Context)
    encoder.enter(nr=asn1.Numbers.Sequence)
    encoder.write("1.2.840.113549.1.1.8", asn1.Numbers.ObjectIdentifier)  # encode pkcs1-MGF oid
    encoder.enter(nr=asn1.Numbers.Sequence)
    encoder.write("2.16.840.1.101.3.4.2.1", asn1.Numbers.ObjectIdentifier)  # encode sha-256 oid
    encoder.leave()
    encoder.leave()
    encoder.leave()
    # encode Context class: two
    encoder.enter(nr=2, cls=asn1.Classes.Context)
    encoder.write(32, asn1.Numbers.Integer)  # encode 32 as integer
    encoder.leave()

    # finish encoding sequenced second part
    encoder.leave()

    # finish encoding main signature id sequence
    encoder.leave()

    return encoder.output()


def replace_signature_id_in_tbs_certificate(tbs_data, new_encoded_signature_id):
    decoder = asn1.Decoder()
    decoder.start(tbs_data)
    decoder.enter()
    version_construct_tag, version_construct_value = decoder.read()
    serial_number_tag, serial_number_value = decoder.read()
    decoder.read()  # ignore old signature_id
    issuer_sequence_tag, issuer_sequence_value = decoder.read()
    validity_sequence_tag, validity_sequence_value = decoder.read()
    subject_sequence_tag, subject_sequence_value = decoder.read()
    subject_pubkeyinfo_sequence_tag, subject_pubkeyinfo_sequence_value = decoder.read()
    extensions_construct_tag, extensions_construct_value = decoder.read()
    decoder.leave()

    # encode new tbs structure
    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(nr=asn1.Numbers.Sequence)
    encoder.write(version_construct_value, nr=version_construct_tag.nr, typ=version_construct_tag.typ,
                  cls=version_construct_tag.cls)
    encoder.write(serial_number_value, nr=serial_number_tag.nr, typ=serial_number_tag.typ, cls=serial_number_tag.cls)

    decoder.start(new_encoded_signature_id)
    new_signatureid_tag, new_signatureid_value = decoder.read()
    encoder.write(new_signatureid_value, nr=new_signatureid_tag.nr, typ=new_signatureid_tag.typ,
                  cls=new_signatureid_tag.cls)

    encoder.write(issuer_sequence_value, nr=issuer_sequence_tag.nr, typ=issuer_sequence_tag.typ,
                  cls=issuer_sequence_tag.cls)
    encoder.write(validity_sequence_value, nr=validity_sequence_tag.nr, typ=validity_sequence_tag.typ,
                  cls=validity_sequence_tag.cls)
    encoder.write(subject_sequence_value, nr=subject_sequence_tag.nr, typ=subject_sequence_tag.typ,
                  cls=subject_sequence_tag.cls)
    encoder.write(subject_pubkeyinfo_sequence_value, nr=subject_pubkeyinfo_sequence_tag.nr,
                  typ=subject_pubkeyinfo_sequence_tag.typ, cls=subject_pubkeyinfo_sequence_tag.cls)
    encoder.write(extensions_construct_value, nr=extensions_construct_tag.nr, typ=extensions_construct_tag.typ,
                  cls=extensions_construct_tag.cls)
    encoder.leave()

    new_tbs_data = encoder.output()
    return new_tbs_data


def encode_signature_and_create_final_structure(data_before_signature, signature_bytes):
    encoder = asn1.Encoder()
    encoder.start()
    encoder.write(signature_bytes, nr=asn1.Numbers.BitString)
    signature_encoded = encoder.output()
    concatenated_all = data_before_signature + signature_encoded
    # put it into sequence
    encoder = asn1.Encoder()
    encoder.start()
    encoder.write(concatenated_all, nr=asn1.Numbers.Sequence, typ=asn1.Types.Constructed)
    final_encoded = encoder.output()
    return final_encoded
