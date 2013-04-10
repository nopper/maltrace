from collections import defaultdict


class Context(object):
    def __init__(self, order, shiftwidth=0):
        self.order = order
        self.kgram = []
        self.counter = defaultdict(int)
        self.positions = defaultdict(list)
        self.shiftwidth = shiftwidth

    def reset(self):
        first, self.kgram = self.kgram[0], self.kgram[1:]
        del self.counter[first]
        if first in self.positions:
            del self.positions[first]

    def add(self, value, position=None):
        """
        Try to add a given value to a k-gram context.
        @param value the value
        @param position the second positional dimension of the value.
        @return False if the Context is full and the value cannot be added.
        """
        # It's pretty contrived
        if len(self.kgram) == 0:
            self.kgram.append(value)
            self.counter[value] += 1

            if position is not None:
                self.positions[value].append(position)

            return True

        is_full = self.is_full()

        if self.kgram[-1] != value:
            if not is_full:
                self.kgram.append(value)
                self.counter[value] += 1

                if position is not None:
                    self.positions[value].append(position)

                return True
            else:
                return False
        else:
            self.counter[value] += 1

            if position is not None:
                self.positions[value].append(position)

            return True

    def is_full(self):
        return len(self.kgram) == self.order

    def to_dimension(self):
        """
        Convert the information collected in form of dimension
        (dimension, value)
        """
        dimension = 0
        dvalue = 0

        for pos, value in enumerate(self.kgram):
            dimension |= value << ((pos) * self.shiftwidth)
            dvalue += self.counter[value]

        return (dimension, dvalue / float(self.order))
