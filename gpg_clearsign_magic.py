#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Jonathan Cervidae <jonathan.cervidae@gmail.com>
# PGP Fingerprint: 2DC0 0A44 123E 6CC2 EB55  EAFB B780 421F BF4C 4CB4
# Last changed: $LastEdit: 2009-05-25 19:34:12 BST$

# TODO: Python only at present
import subprocess
import sys
import os
import tempfile
import shutil
import re
import magic
import gpgme
from StringIO import StringIO

class Signer(object):
    def __init__(self,data=None,fingerprint=None,gpg_directory=None):
        if not data:
            raise TypeError, "You didn't supply any data"
        if not fingerprint:
            raise TypeError, "You didn't supply a fingerprint"
        if gpg_directory:
            os.environ['GNUPGHOME'] = gpg_directory
        ctx = self.ctx = gpgme.Context()
        ctx.armor = True
        key = ctx.get_key(fingerprint)
        ctx.signers = [key]
        self.signed = None
        if self.has_signature(data):
            data = self.strip_signature(data)
        self.data = data
        self.file_type = self.identify()
    def __str__(self):
        if not self.signed:
            self.sign()
        return self.signed
    def has_signature(self, data):
        return False
        raise NotImplementedError
    def sign(self):
        signed = StringIO()
        if self.file_type in self.file_signature_table:
            data, header_open, header_close, footer_open, footer_close = (
                self.file_signature_table[self.file_type](self)
            )
            to_be_signed = StringIO(header_close + data + footer_open)
            self.ctx.sign(to_be_signed, signed, gpgme.SIG_MODE_CLEAR)
            self.signed = (
                header_open +
                signed.getvalue() +
                footer_close
            )
        else:
            raise NotImplementedError, "I don't know how to handle %s" % \
                self.magic_identity
        return self.signed
    def template_python(self):
        # FIXME: Doesn't handle UTF-8 file marker
        header = ""
        lines = self.data.splitlines(True)
        lines_consumed = 0
        coding_range = (1,2)
        if lines[0][0:2] == "#!":
            header += lines[0]
            lines_consumed += 1
        else:
            coding_range = (0,2)
        coding_re = re.compile("^# -\*- coding: .+ -\*-$")
        for line_number in coding_range:
            line = lines[line_number]
            if coding_re.match(line):
                lines_consumed += 1
                header += line
        header += '__pgp_header__ = """' + os.linesep
        footer = os.linesep + '__pgp_signature__ = """' + os.linesep
        trailer = '"""' + os.linesep
        data = "".join(lines[lines_consumed:])
        return (data, header, '"""' + os.linesep, footer, trailer)
    def strip_python(self):
        raise NotImplementedError

    def identify(self):
        self.magic_identity = magic.from_buffer(self.data)
        if self.magic_identity in Signer.file_magic_table:
            return (
                Signer.file_magic_table[
                    self.magic_identity
                ]
            )
    file_magic_table = {
        "a python script text executable": "python"
    }
    file_signature_table = {
        "python": template_python
    }

if __name__ == "__main__":
    sys.stdout.write(str(Signer(sys.stdin.read())))


# Left here as notes for re-implementing javascript handling later
#    out, err = proc.communicate(
#        "*/%s%s/*" % (os.linesep, js)
#    )
#    sys.stdout.write( "/*%s%s*/%s" % ( os.linesep, out, os.linesep ) )
#    sys.stdout.flush()

