#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Jonathan Cervidae <jonathan.cervidae@gmail.com>
# PGP Fingerprint: 2DC0 0A44 123E 6CC2 EB55  EAFB B780 421F BF4C 4CB4
# Last changed: $LastEdit: 2009-05-24 23:17:20 BST$

# TODO: Javascript only at present
import subprocess
import sys
import os
import tempfile
import shutil
import re

class Signer(object):
    class FIFO(file):
        def __init__(self, string):
            self.temp_path = tempfile.mkdtemp()
            fifo_name = tempfile.mktemp(dir=self.temp_path)
            os.mkfifo(fifo_name,0600)
            super(Signer.FIFO, self).__init__(fifo_name, "ab+", 0)
        def __del__(self):
#            super(Signer.FIFO, self).__del__()
            self.close()
            shutil.rmtree(self.temp_path, ignore_errors=False)
    def __init__(self,data):
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

    def call_command(self,args, data=None):
        if data:
            proc = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,stdout=subprocess.PIPE
            )
            out, err = proc.communicate(data)
        else:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE
            )
            out, err = proc.communicate()
        if proc.returncode is not 0:
            raise StandardError, (
                "%s has problem:%s%s" % (
                    args[0], os.linesep * 2, err
                )
            )
        return(out)
    def sign(self):
        data = self.data
        args = ("gpg", "--output", "-", "--clearsign", "-")
        if self.file_type in self.file_signature_table:
            sys.stderr.write("Monkey")
            data, header_open, header_close, footer_open, footer_close = (
                self.file_signature_table[self.file_type](self)
            )
            self.signed = (
                header_open +
                self.call_command(args, header_close + data + footer_open) +
                footer_close
            )
        else:
            self.signed = self.call_command(args, data)
        return self.signed
    def process_python(self):
        header = ""
        lines = self.data.splitlines()
        # FIXME: Doesn't handle UTF-8 file marker
        lines_consumed = 0
        coding_range = (1,2)
        if lines[0][0:2] == "#!":
            header += lines[0] + os.linesep
            lines_consumed += 1
        else:
            coding_range = (0,2)
        # -*- coding: utf-8 -*-
        coding_re = re.compile("^# -\*- coding: .+ -\*-$")
        for line_number in coding_range:
            line = lines[line_number]
            if coding_re.match(line):
                lines_consumed += 1
                header += line + os.linesep
        header += '__pgp_header__ = """' + os.linesep
        footer = os.linesep + '__pgp_signature__ = """' + os.linesep
        trailer = '"""'
        data = os.linesep.join(lines[lines_consumed:])
        return (data, header, '"""' + os.linesep, footer, trailer)


    def identify(self):
        # FIXME: Not portable
        fifo = self.FIFO(self.data)
        fifo.write(self.data)
        file_command_says = self.call_command(
            ("file", "-s", fifo.name)
        )
        return (
            Signer.file_magic_table[
                file_command_says[len(fifo.name)+2:].strip()
            ]
        )
    file_magic_table = {
        "a python script text executable": "python"
    }
    file_signature_table = {
        "python": process_python
    }

if __name__ == "__main__":
    sys.stdout.write(str(Signer(sys.stdin.read())))


#    out, err = proc.communicate(
#        "*/%s%s/*" % (os.linesep, js)
#    )
#    sys.stdout.write( "/*%s%s*/%s" % ( os.linesep, out, os.linesep ) )
#    sys.stdout.flush()

