#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Jonathan Cervidae <jonathan.cervidae@gmail.com>
# PGP Fingerprint: 2DC0 0A44 123E 6CC2 EB55  EAFB B780 421F BF4C 4CB4
# Last changed: $LastEdit: 2009-05-25 07:48:56 BST$

from gpg_clearsign_magic import *

# gpg --no-default-keyring --local-user B2C7419F --secret-keyring
# ./secring.gpg --primary-keyring ./pubring.gpg --output - --clearsign
# test-gpg-clearsign-magic.py

class TestSigningOfFiles(object):
    """I can sign, unsign and resign files with the GPG program using the
    default signature key"""
    def test_can_identify_a_file_as_a_python_file(self):
        signer = Signer(open("test-gpg-clearsign-magic.py").read())
        assert signer.file_type == "python"
    def test_can_sign_a_python_file_without_modifying_its_function(self):
        signer = Signer(open("test-gpg-clearsign-magic.py").read())
        signed = signer.sign()
        f = open("test.signed","w")
        f.write(signed)
    def test_can_strip_a_signature_from_a_python_file(self):
        raise NotImplementedError
