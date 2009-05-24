#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Jonathan Cervidae <jonathan.cervidae@gmail.com>
# PGP Fingerprint: 2DC0 0A44 123E 6CC2 EB55  EAFB B780 421F BF4C 4CB4
# Last changed: $LastEdit: 2009-05-24 22:09:01 BST$

from gpg_clearsign_magic import *

class TestSigningOfFiles(object):
    """I can sign, unsign and resign files with the GPG program using the
    default signature key"""
    def test_can_identify_a_file_as_a_python_file(self):
        signer = Signer(open("test-gpg-clearsign-magic.py").read())
        assert signer.file_type == "python"
    def test_can_sign_a_python_file_without_modifying_its_function(self):
        raise NotImplementedError
    def test_can_strip_a_signature_from_a_python_file(self):
        raise NotImplementedError
