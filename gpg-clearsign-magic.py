#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Jonathan Cervidae <jonathan.cervidae@gmail.com>
# PGP Fingerprint: 2DC0 0A44 123E 6CC2 EB55  EAFB B780 421F BF4C 4CB4
# Last changed: $LastEdit: 2009-05-16 18:53:50 BST$

# TODO: Javascript only at present
import subprocess
import sys
import os

for file_name in sys.argv[1:]:
    if file_name == "-":
        js = sys.stdin.read()
    else:
        js = open(file_name).read()

    proc = subprocess.Popen(("gpg", "--output", "-", "--clearsign",
    "-"),stdin=subprocess.PIPE,stdout=subprocess.PIPE)

    out, err = proc.communicate(
        "*/%s%s/*" % (os.linesep, js)
    )
    sys.stdout.write( "/*%s%s*/%s" % ( os.linesep, out, os.linesep ) )
    sys.stdout.flush()

