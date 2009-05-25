#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Jonathan Cervidae <jonathan.cervidae@gmail.com>
# PGP Fingerprint: 2DC0 0A44 123E 6CC2 EB55  EAFB B780 421F BF4C 4CB4
# Last changed: $LastEdit: 2009-05-25 17:38:28 BST$

from gpg_clearsign_magic import *
import subprocess
import sys
import os


KEYRING_PATH = os.path.abspath(sys.path[0])
FINGERPRINT = "9F5975B13C1803F804B0615C7C7A4335B2C7419F"

class TestSigningOfFiles(object):
    """I can sign, unsign and resign files with the GPG program using the
    default signature key"""

    def setUp(self):
        self.signer = Signer(
            data=open("test-gpg-clearsign-magic.py").read(),
            gpg_directory=KEYRING_PATH,
            fingerprint=FINGERPRINT
        )
    def test_can_identify_a_file_as_a_python_file(self):
        assert self.signer.file_type == "python"
    def test_can_sign_a_python_file_without_modifying_its_function(self):
        signed = self.signer.sign()
        f = open("test.signed","w")
        f.write(signed)
    def test_can_strip_a_signature_from_a_python_file(self):
        raise NotImplementedError
