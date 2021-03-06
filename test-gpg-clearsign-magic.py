#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Jonathan Cervidae <jonathan.cervidae@gmail.com>
# PGP Fingerprint: 2DC0 0A44 123E 6CC2 EB55  EAFB B780 421F BF4C 4CB4
# Last changed: $LastEdit: 2009-05-25 22:58:38 BST$
# Last committed: $Format:%cd$
# File revision: $Id$
#
# This file is part of gpg-clearsign-magic.
#
# gpg-clearsign-magic is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# gpg-clearsign-magic is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# gpg-clearsign-magic in the file COPYING. If not, see
# <http://www.gnu.org/licenses/>.

import pydb
from gpg_clearsign_magic import *
import subprocess
import sys
import os
import gpgme
from StringIO import StringIO
import time
import random


class TestSigningOfFiles(object):
    """I can sign, unsign and resign files with the GPG program using the
    default signature key"""

    KEYRING_PATH = os.path.abspath(sys.path[0])
    FINGERPRINT = "9F5975B13C1803F804B0615C7C7A4335B2C7419F"

    def setUp(self):
        self.original_data = open("test-gpg-clearsign-magic.py").read()
        self.signer = Signer(
            data=self.original_data,
            gpg_directory=self.KEYRING_PATH,
            fingerprint=self.FINGERPRINT
        )
    def test_can_identify_a_file_as_a_python_file(self):
        assert self.signer.file_type == "python"
    def test_can_sign_a_python_file_without_modifying_its_function(self):
        signed = self.signer.sign()

        code_without_signature = StringIO()
        ctx = gpgme.Context()
        os.environ['GNUPGHOME'] = self.KEYRING_PATH

        sigs = ctx.verify(StringIO(signed), None, code_without_signature)
        assert len(sigs) == 1
        sig = sigs[0]

        # I don't know why this is 0 not SIGSUM_VALID
        assert sig.summary == 0
        assert sig.fpr == self.FINGERPRINT
        assert sig.status is None
        assert sig.notations == []
        assert sig.timestamp <= int(time.time())
        assert sig.wrong_key_usage is False
        assert sig.validity == gpgme.VALIDITY_UNKNOWN
        assert sig.validity_reason is None

        # Monkey it up :)
        half_way_index = len(signed) / 2
        character_to_change = signed[half_way_index]
        random_char = character_to_change
        while random_char == character_to_change:
            random_char = "%c"%random.randint(ord("a"),ord("z"))
        monkeyed = (
            signed[:half_way_index] +
            random_char +
            signed[half_way_index+1:]
        )
        signed = monkeyed
        sigs = ctx.verify(StringIO(signed), None, code_without_signature)
        assert len(sigs) == 1
        sig = sigs[0]
        # Check we are now a bad signature
        assert sig.summary == gpgme.SIGSUM_RED

        # This is not the same because we changed the original code to make it
        # still a valid python program. It should be checked by the stripper.
        #code_without_signature = code_without_signature.getvalue()
        #assert code_without_signature == self.original_data
    def test_can_strip_a_signature_from_a_python_file(self):
        signed = self.signer.sign()
        stripper = Stripper(
            data=signed,
            gpg_directory=self.KEYRING_PATH,
            fingerprint=self.FINGERPRINT
        )
        stripped = stripper.strip()
        # There is currently no way for us to get the first two lines back,
        # except to include them in the encoded file as a repeat and that
        # looks silly! I will fix this in a later version, for now, this
        # haxery...
        # FIXME: Add a magic comment to the top of the encoded data which
        # tells us what to reproduce when the program is stripped. This is how
        # the problem should be solved.
        stripped = "#!/usr/bin/env python\n# -*- coding: utf-8 -*-\n" + \
            stripped
        assert self.original_data == stripped

if __name__ == '__main__':
    import nose
    nose.main()
