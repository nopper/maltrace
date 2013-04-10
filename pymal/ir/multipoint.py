import json
import math


class MultiPoint(object):
    def __init__(self, name, *dimensions):
        self.name = name
        self.dimensions = {}

        for point in dimensions:
            self.add_dimension(*point)

    def to_json(self):
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(self, value):
        inst = MultiPoint(value['name'])
        inst.dimensions = value['dimensions']
        return inst

    def __str__(self):
        return ', '.join(["%s: %s" % (k, v) for k, v in sorted(self.dimensions.iteritems())])

    def add_dimension(self, dimension, position, logscale=True):
        # Just apply a simple log-TF scheme without IDF, since the
        # collection is not static but dynamic.

        if logscale:
            prev = self.dimensions.get(dimension, 0)
            new = 1 + math.log(position)

            if new > prev:
                self.dimensions[dimension] = new
        else:
            self.dimensions[dimension] = self.dimensions.get(dimension, 0) + position

    def get_similarity(self, other, collect=False):
        """
        Implement simple cosine similarity between two MultiPoint objects
        """
        a, b = self.dimensions, other.dimensions

        # Just try to minimize the intersection cost
        if len(b) < len(a):
            b, a = a, b

        collector = []

        accumulator = 0
        denoma, denomb = 0, 0

        for dimension in a:
            #if dimension in b:
            vala = a.get(dimension, 0)
            valb = b.get(dimension, 0)

            if collect and (vala != 0 and valb != 0):
                collector.append((dimension, vala * valb))

            accumulator += vala * valb
            denoma += vala * vala
            denomb += valb * valb

        if not accumulator:
            ret = 0.0
        else:
            ret = accumulator / (math.sqrt(denoma) * math.sqrt(denomb))

        if collect:
            return ret, collector
        else:
            return ret
