from pylab import *
from pymal.analyzer import Analyzer
from collections import defaultdict

app = Analyzer('simple.db')

def get_timeline(sampleid, clean):
    callers = set()
    for num, caller in app.foreach_syscall(sampleid, 0):
        if clean and (caller == '0x00000000' or caller in callers):
            continue
        yield (num, int(caller[2:], 16))
        callers.add(caller)

def kgrammify(timeline, k):
    kgram = []
    for x in xrange(k):
        kgram.append((0, 0))

    for x in timeline:
        kgram.pop(0)
        kgram.append(x)
        yield tuple(kgram)

    for x in xrange(k - 1):
        kgram.pop(0)
        kgram.append((0, 0))
        yield tuple(kgram)

CLEANED = False
KGRAM = 1

labels = map(lambda x: x[1], app.get_samples())
timelines = dict([(sample, get_timeline(id, CLEANED)) for id, sample in app.get_samples()])

# for name, points in sorted(timelines.iteritems()):
#   y = map(lambda x: x[0], points)
#   #x = map(lambda x: x[1], points)
#   #plot(x, y, linestyle='none', marker='o')
#   plot(y, linestyle='none', marker='o')

figure(figsize=(7, 7))

k = []
for name, points in sorted(timelines.iteritems()):
    counter = 0
    pdf = defaultdict(int)
    kgrams = []

    for kgram in kgrammify(points, KGRAM):
        hashed = 0
        for num, off in kgram:
            hashed = hashed << 9
            hashed ^= num

        pdf[hashed] += 1
        counter += 1
        kgrams.append(hashed)

    y = []
    x = []
    for num, value in sorted(pdf.iteritems()):
        prob = value * 1.0 / counter
        #if prob < 0.001:
        y.append(prob)
        x.append(num)

    #plot(y, linestyle='none', marker='x')
    plot(x, y, marker='x')
    #k.append(kgrams)
#hist(k, alpha=0.5)


legend(labels)
title('%d-gram PDF%s' % (KGRAM, CLEANED and ' (No nested)' or ''))
ylabel('Probability')
xlabel(KGRAM == 1 and 'Syscall number' or 'Hashed syscall %d-grams' % KGRAM)
show()
