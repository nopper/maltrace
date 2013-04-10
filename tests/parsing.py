import os
import sys
import unittest

sys.path.insert(0, os.getcwd())
from pymal.grammar import get_grammar, parse, Variable

FIXTURE_RECURSIVE = """
PIO_STATUS_BLOCK IoStatusBlock = {
    PVOID Pointer = 0x00000103
    ULONG Status = 12855664
    ULONG Information = 12855664
    PIO_STATUS_BLOCK IoStatusBlock = {
        PVOID Pointer = 0x00000103
        ULONG Status = 12855664
        ULONG Information = 12855664
        PIO_STATUS_BLOCK IoStatusBlock = {
            PVOID Pointer = 0x00000103
            ULONG Status = 12855664
            ULONG Information = 12855664
            PUNICODE_STRING ObjectName = \"\"\"\Registry\Machine\System\CurrentControlSet\Control\Srp\GP\DLL\"\"\"
        }
    }
}"""

FIXTURE_POINT = """
A a = {
    B a.b.c.d = 24
    C e.f.g.h = 42
}
"""

class TestParsing(unittest.TestCase):
    def test_grammar(self):
        expr = get_grammar()
        ret = expr.parseString(FIXTURE_RECURSIVE)

        expected = ['PIO_STATUS_BLOCK', 'IoStatusBlock', '=', [
            'PVOID', 'Pointer', '=', '0x00000103',
            'ULONG', 'Status', '=', '12855664',
            'ULONG', 'Information', '=', '12855664',
            'PIO_STATUS_BLOCK', 'IoStatusBlock', '=', [
                'PVOID', 'Pointer', '=', '0x00000103',
                'ULONG', 'Status', '=', '12855664',
                'ULONG', 'Information', '=', '12855664',
                'PIO_STATUS_BLOCK', 'IoStatusBlock', '=', [
                'PVOID', 'Pointer', '=', '0x00000103',
                'ULONG', 'Status', '=', '12855664',
                'ULONG', 'Information', '=', '12855664',
                'PUNICODE_STRING', 'ObjectName', '=', '\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Srp\\GP\\DLL']]]]

            # Kinda lame but at least we have it
        self.assertTrue(str(ret) == str(expected))

    def test_point_struct(self):
        ret = get_grammar().parseString(FIXTURE_POINT)
        expected = ['A', 'a', '=', ['B', 'a.b.c.d', '=', '24', 'C', 'e.f.g.h', '=', '42']]
        self.assertTrue(str(ret) == str(expected))

    def test_parse(self):
        # Well that's pretty awesome
        ret = parse("""A a = { B b = 2 }""")
        self.assertTrue(ret[0], Variable('A', 'a', Variable('B', 'b', '2')))


if __name__ == '__main__':
    unittest.main()