#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Jonathan Cervidae <jonathan.cervidae@gmail.com>
# PGP Fingerprint: 2DC0 0A44 123E 6CC2 EB55  EAFB B780 421F BF4C 4CB4
# Last changed: $LastEdit: 2009-05-24 22:08:38 BST$

# TODO: Javascript only at present
import subprocess
import sys
import os
import tempfile
import shutil

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
        if self.has_signature(data):
            data = self.strip_signature(data)
        self.data = data
        self.file_type = self.identify()
        print self.file_type
    def __str__(self):
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
        return self.call_command(
            ("gpg", "--output", "-", "--clearsign", "-"), self.data
        )
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


if __name__ == "__main__":
    sys.stdout.write(str(Signer(sys.stdin.read())))


#    out, err = proc.communicate(
#        "*/%s%s/*" % (os.linesep, js)
#    )
#    sys.stdout.write( "/*%s%s*/%s" % ( os.linesep, out, os.linesep ) )
#    sys.stdout.flush()

