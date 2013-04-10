import os
import sys
import unittest

sys.path.insert(0, os.getcwd())
from pymal.ir.context import Context
from pymal.ir.multipoint import MultiPoint

class TestParsing(unittest.TestCase):
    def setUp(self):
        pass

    def test_similar(self):
        a = MultiPoint(None, (1, 4), (0, 3))
        self.assertTrue(a.get_similarity(a) == 1.0)


class TestContext(unittest.TestCase):
    def test_full(self):
        ctx = Context(1)
        self.assertTrue(ctx.add(0))
        self.assertTrue(ctx.add(0))
        self.assertFalse(ctx.add(1))

        ctx = Context(2)
        self.assertTrue(ctx.add(0))
        self.assertTrue(ctx.add(0))
        self.assertTrue(ctx.add(1))
        self.assertTrue(ctx.add(1))
        self.assertFalse(ctx.add(0))

    def test_fistorder(self):
        ctx = Context(1)
        ctx.add(0)
        self.assertTrue(ctx.to_dimension() == (0, 1))

    def test_secondorder(self):
        ctx = Context(2, 2)
        ctx.add(1)
        ctx.add(2)
        self.assertTrue(ctx.to_dimension() == (9, 1))

    def test_ngram(self):
        ctx = Context(2, 2)
        ctx.add(1)
        ctx.add(2)
        self.assertTrue(ctx.kgram == [1, 2])
        ctx.reset()
        self.assertTrue(ctx.kgram == [2])
        ctx.add(2)
        self.assertTrue(ctx.kgram == [2])
        ctx.add(3)
        self.assertTrue(ctx.kgram == [2, 3])
        self.assertFalse(ctx.add(4))

    def test_position(self):
        actx = Context("positional-a", 1)
        actx.add(1, 0)
        actx.add(1, 2)

        bctx = Context("positional-b", 1)
        bctx.add(1, 1)
        bctx.add(1, 2)



if __name__ == '__main__':
    unittest.main()
