"""
This module is a collector that takes in input the syscall trace log and
generates the sqlite database which can be then queried for further malware
analysis.
"""

import os
import re
import sys
import json
#import mmap
import sqlite3

from optparse import OptionParser

from grammar import parse
from logger import get_logger

# [thread id 0] SYSCALL 191 (ZwOpenProcessToken): 0x76eb7092 (0xffffffff, 0x8, 0x1cf464)
#   HANDLE ProcessHandle = 0xFFFFFFFF
#   ULONG DesiredAccess = 8
#   HANDLE TokenHandle = 0x001CF464
# [thread id 0] SYSCALL 191 (ZwOpenProcessToken): returns: 0x0

# Pretty complicated regex. This should be tested.
REGEX = r'\[thread\sid\s(\d+)\]\sSYSCALL\s(\d+)\s\((\w+)\):\s'   \
         '(0x[0-9a-fA-F]+)\s(0x[0-9a-fA-F]+)\s\(([^\)]*)\)(.*?)\[thread\sid\s(\d+)\]' \
         '\sSYSCALL\s(\d+)\s\((\w+)\):\sreturns:\s(0x[0-9a-fA-F]+)' \
         '\scaller:\s(0x[0-9a-fA-F]+)'

REGEX = r'\[thread\sid\s(\d+)\]\sSYSCALL\s(\d+)\s\((\w+)\):\s(0x[0-9a-fA-F]+)\s(0x[0-9a-fA-F]+)\s(0x[0-9a-fA-F]+)\s\(([^\)]*)\)(.*?)\['

log = get_logger('collector')


class LogReader(object):
    def __init__(self, options, args):
        create = not os.path.exists(args[0])
        self.db = sqlite3.connect(args[0])
        self.rex = re.compile(REGEX, re.MULTILINE | re.DOTALL)
        self.create_schema(create)

    def create_schema(self, drop):
        if not drop:
            return

        cur = self.db.cursor()

        cur.execute('''DROP TABLE IF EXISTS SAMPLES''')
        cur.execute('''DROP TABLE IF EXISTS EVENTS''')

        cur.execute('''CREATE TABLE SAMPLES(
                       ID INTEGER PRIMARY KEY AUTOINCREMENT,
                       NAME TEXT)''')
        cur.execute('''CREATE TABLE EVENTS(
                       ID INTEGER PRIMARY KEY AUTOINCREMENT,
                       SAMPLEID REFERENCES SAMPLES(ID),
                       THREADID INTEGER,
                       SYSCALLNUM INTEGER,
                       SYSCALLNAME TEXT(30),
                       EIP TEXT,
                       HEXARGS TEXT,
                       ARGS TEXT,
                       RET TEXT,
                       CALLER TEXT)''')
        self.db.commit()

    def read_file(self, fname):
        """
        Simple generator to parse log files
        """
        # Here we try to memory map the file and just use the findall
        with open(fname, 'r') as logfile:
            #contents = mmap.mmap(logfile.fileno(), os.stat(fname).st_size)
            contents = logfile.read()
            for match in self.rex.finditer(contents, re.MULTILINE | re.DOTALL):
                thread_id = match.group(1)
                syscall_number = match.group(2)
                syscall_name = match.group(3)
                eip = match.group(4)
                caller = match.group(5)
                caller_offset = match.group(6)
                hexargs = match.group(7)
                args = match.group(8)
                #ret = match.group(12)
                ret = ''

                hexargs = map(lambda x: x.strip(), hexargs.strip().split(','))
                args = parse(args)

                yield (thread_id, syscall_number, syscall_name, eip, hexargs, args, ret, caller_offset)

    def get_id(self, samplename):
        cur = self.db.cursor()
        cur.execute('SELECT ID FROM SAMPLES WHERE NAME = ? LIMIT 1', (samplename, ))
        value = cur.fetchone()

        if value is not None:
            value = value[0]

        return value

    def run(self, fname, samplename):
        cur = self.db.cursor()

        # Let's create our entry in the samples tables
        sample_id = self.get_id(samplename)

        if sample_id is not None:
            log.critical("A sample with the same name (%s) already exists with ID=%d" % \
                         (samplename, sample_id))
            return

        cur.execute('INSERT INTO SAMPLES VALUES(NULL, ?)', (samplename, ))
        sample_id = self.get_id(samplename)

        log.info("Sample '%s' inserted in the database with ID=%d" % (samplename, sample_id))

        for idx, (thread_id, syscall_number, syscall_name,
             eip, hexargs, args, ret, caller) in enumerate(self.read_file(fname)):

                hexargs = json.dumps(hexargs)
                args = json.dumps(args)

                # May be here after the parse we should send the strings to a parsing
                # pipeline that tries to extract useful strings from the log.

                cur.execute('INSERT INTO EVENTS VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (
                        sample_id, thread_id, syscall_number, syscall_name,
                        eip, hexargs, args, ret, caller
                    )
                )

        log.info("%d syscalls extracted." % (idx + 1))

        self.db.commit()


if __name__ == '__main__':
    parser = OptionParser(usage="Usage: %s <dbfile> <logfile> <samplename>" % sys.argv[0])

    (options, args) = parser.parse_args()

    if len(args) != 3:
        parser.print_usage()
        parser.print_help()
        sys.exit(-1)
    else:
        LogReader(options, args).run(args[1], args[2])
        sys.exit(0)
