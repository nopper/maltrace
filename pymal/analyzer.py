import sys
import math
import sqlite3
from optparse import OptionParser
from collections import defaultdict

from logger import get_logger
from ir.context import Context
from ir.multipoint import MultiPoint
from fsm import FSM

log = get_logger('analyzer')

MAXSYSCALL = 512
BITMASK = MAXSYSCALL - 1
SHIFTWIDTH = int(round(math.log(MAXSYSCALL) / math.log(2)))


class Analyzer(object):
    def __init__(self, dbfile):
        self.db = sqlite3.connect(dbfile)

    def get_fsm(self, sample_id):
        """
        Return a FSM representation taking in consideration 1-gram sequence
        """
        fsm = FSM()

        for thread_id, total in self.get_stats_for(sample_id):
            sfrom = 'start'

            for num, caller in self.foreach_syscall(sample_id, thread_id):
                fsm.add(sfrom, num, num)
                sfrom = num

        fsm.start('start')
        return fsm

    def foreach_syscall(self, sample_id, thread_id):
        """
        Iterate over the database collection in time-order
        returning (syscallnum, caller) tuples
        """
        cur = self.db.cursor()
        cur.execute('''SELECT SYSCALLNUM, CALLER
                       FROM EVENTS WHERE SAMPLEID=? AND THREADID=?
                       ORDER BY ID ASC''', (sample_id, thread_id, ))

        row = cur.fetchone()

        while row:
            yield row
            row = cur.fetchone()

    def get_stats_for(self, sample_id):
        cur = self.db.cursor()
        cur.execute('''SELECT THREADID, COUNT(THREADID) FROM EVENTS
                       WHERE SAMPLEID=? GROUP BY(THREADID)''', (sample_id, ))
        return cur.fetchall()

    def get_samples(self):
        cur = self.db.cursor()
        cur.execute('SELECT ID, NAME FROM SAMPLES')

        return cur.fetchall()

    def get_id_for(self, samplename):
        cur = self.db.cursor()
        cur.execute('SELECT ID FROM SAMPLES WHERE NAME = ? LIMIT 1', (samplename, ))
        value = cur.fetchone()

        if value is not None:
            value = value[0]

        return value

    def get_ksimilarities(self, korder):
        vectors = []

        for row in self.get_samples():
            vectors.append((row[1],
                self.get_kcontext_for(row[0], korder, True, False),
                self.get_kcontext_for(row[0], korder, True, True)))

        similarities = defaultdict(dict)

        for sname, src, csrc in vectors:
            for dname, dst, cdst in vectors:
                if src is dst:
                    continue

                sim = src.get_similarity(dst)
                csim = csrc.get_similarity(cdst)
                similarities[sname][dname] = (sim, csim)
                similarities[dname][sname] = (sim, csim)

        return similarities

    def get_unique_kgrams(self, sample, start, stop):
        sample_id = self.get_id_for(sample)
        summary = []

        for k in xrange(start, stop + 1):
            summary.append(len(self.get_kcontext_for(sample_id, k).dimensions))

        return summary

    def get_kpdf_for(self, sample, korder):
        sample_id = self.get_id_for(sample)
        info = self.get_kcontext_for(sample_id, korder, False)

        normal = 0

        for k, v in info.dimensions.iteritems():
            normal += v

        kgrams = []

        for k, v in info.dimensions.iteritems():
            kgrams.append((k, 1.0 * v / normal))

        # Sort by value descending
        #kgrams.sort(reverse=True, key=lambda x: x[1])

        return kgrams

    def unpack_kgram_value(self, value, korder):
        temp = value
        cur = self.db.cursor()
        syscalls = []

        for i in xrange(korder):
            syscallnum = temp & BITMASK
            cur.execute("SELECT SYSCALLNAME FROM EVENTS WHERE SYSCALLNUM=? LIMIT 1", (syscallnum, ))
            syscalls.append((syscallnum, cur.fetchone()[0]))
            temp = temp >> SHIFTWIDTH

        return syscalls

    def get_kcontext_for(self, sample_id, korder, logscale=True, clean=True):
        # Conta che non teniamo in considerazione dell'ordine, ne dei parametri
        # Sarebbe interessante fare un coalesce sugli handle
        # E seguire i file soprattutto i file CreateFile, WriteFile
        # o le porte NtCreatePort
        # o i socket
        # o le stringhe

        kcontext = Context(korder, SHIFTWIDTH)
        info = MultiPoint('%d-order' % korder)

        psyscall, pcaller = 0, '0x00000000'

        for thread_id, total in self.get_stats_for(sample_id):
            #log.info("\tThread %3d with %5d syscall invocations" % (thread_id, total))

            total = float(total)
            for syscall, caller in self.foreach_syscall(sample_id, thread_id):

                # Firstly, let's ignore every syscall that has no apparent caller
                # in the .text section of our program
                if clean and caller == '0x00000000':
                    continue

                # Here we assume that a sequence of syscall invocations
                # that share the same caller address are actually in-syscall invocations.
                # For this reasons they are ignored

                if clean and pcaller == caller:
                    continue

                # If we don't succeed at adding we are full and
                # the just attempted value was not the same as the
                # last added value.
                if not kcontext.add(syscall):
                    info.add_dimension(*kcontext.to_dimension(), logscale=logscale)
                    #print kcontext.kgram
                    kcontext.reset()
                    kcontext.add(syscall)

                psyscall, pcaller = syscall, caller

        info.add_dimension(*kcontext.to_dimension(), logscale=logscale)
        return info

class ConsoleAnalyzer(Analyzer):
    """
    Just a realization to print information on the console
    """
    def print_samples(self):
        for id, name in self.get_samples():
            log.info("ID: %03d - Name: %10s" % (id, name))

    def print_ksimilarities(self, korder):
        similarities = self.get_ksimilarities(korder)

        for k1 in sorted(similarities):
            log.info("Summary for %s" % k1)
            for k2 in sorted(similarities[k1]):
                log.info("\t => %10s: %.4f clean: %.4f" % \
                    (k2, similarities[k1][k2][0], similarities[k1][k2][1]))

    def print_unique_kgrams(self, sample, start, stop):
        for pos, point in enumerate(self.get_unique_kgrams(sample, start, stop)):
            log.info("%d %d" % (pos + start, point))

    def print_kpdf_for(self, sample, korder):
        for k, v in self.get_kpdf_for(sample, korder):
            log.info("%d %f" % (k, v))

if __name__ == '__main__':
    parser = OptionParser(usage="Usage: %s <dbfile>" % sys.argv[0])
    parser.add_option("-l", "--list",
                      action="store_true", dest="list", default=False,
                      help="List all the samples")
    parser.add_option("-s", "--sample",
                      action="store", type="string", dest="sample",
                      help="Malware to analyze")
    parser.add_option("-k", "--kgram",
                      action="store", type="string", dest="kgrams",
                      help="K-gram interval to study. Ex: 1:20")
    parser.add_option("-p", "--pdf",
                      action="store", type="string", dest="pdf",
                      help="Extract a pdf from the k-grams")
    parser.add_option("-c", "--cosine",
                      action="store", dest="cosine", default="3",
                      help="Compute cosine similarity of k order. Ex: -c 3")
    (options, args) = parser.parse_args()

    if len(args) != 1:
        parser.print_usage()
        parser.print_help()
        sys.exit(-1)
    else:
        app = ConsoleAnalyzer(args[0])

        if options.list:
            app.print_samples()
        elif options.sample is not None:
            if options.kgrams is not None:
                start, stop = options.kgrams.split(':', 1)
                start = max(int(start), 1)
                stop = max(stop, int(stop))
                app.print_unique_kgrams(options.sample, start, stop)
            elif options.pdf is not None:
                kgram = int(options.pdf)
                app.print_kpdf_for(options.sample, kgram)
        elif options.cosine:
            app.print_ksimilarities(int(options.cosine))
        else:
            parser.print_usage()
            parser.print_help()
            sys.exit(-1)

        sys.exit(0)
