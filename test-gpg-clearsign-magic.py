#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Jonathan Cervidae <jonathan.cervidae@gmail.com>
# PGP Fingerprint: 2DC0 0A44 123E 6CC2 EB55  EAFB B780 421F BF4C 4CB4
# Last changed: $LastEdit: 2009-05-25 18:40:58 BST$

import pydb
from gpg_clearsign_magic import *
import subprocess
import sys
import os
import gpgme
from StringIO import StringIO
import time

KEYRING_PATH = os.path.abspath(sys.path[0])
FINGERPRINT = "9F5975B13C1803F804B0615C7C7A4335B2C7419F"

class TestSigningOfFiles(object):
    """I can sign, unsign and resign files with the GPG program using the
    default signature key"""

    def setUp(self):
        self.original_data = open("test-gpg-clearsign-magic.py").read()
        self.signer = Signer(
            data=self.original_data,
            gpg_directory=KEYRING_PATH,
            fingerprint=FINGERPRINT
        )
    def test_can_identify_a_file_as_a_python_file(self):
        assert self.signer.file_type == "python"
    def test_can_sign_a_python_file_without_modifying_its_function(self):
        global KEYRING_PATH
        global FINGERPRINT
        signed = self.signer.sign()
        original_code = StringIO()
        ctx = gpgme.Context()
        os.environ['GNUPGHOME'] = KEYRING_PATH
        sigs = ctx.verify(StringIO(signed), None, original_code)
        assert len(sigs) == 1
        sig = sigs[0]
        assert sig.summary == 0
        assert sig.fpr == FINGERPRINT
        assert sig.status is None
        assert sig.notations == []
        assert sig.timestamp <= int(time.time())
        assert sig.wrong_key_usage is False
        assert sig.validity == gpgme.VALIDITY_UNKNOWN
        assert sig.validity_reason is None
        original_code = original_code.getvalue()
        #assert original_code == self.original_data
        f = open("signed","w")
        f.write(signed)
        f.close()
        f = open("original","w")
        f.write(self.original_data)
        f.close()
        f = open("decoded","w")
        f.write(original_code)
        f.close()
    def test_can_strip_a_signature_from_a_python_file(self):
        raise NotImplementedError
