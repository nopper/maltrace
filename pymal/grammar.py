"""
Simple parser for the log arguments exploiting pyparsing
"""
from collections import namedtuple
from pyparsing import Literal, Word, Regex, ZeroOrMore, \
                      alphas, QuotedString, nums, Forward, Group

Variable = namedtuple('Variable', ['type', 'name', 'value'])


def parse(text):
    """
    Return a structured list of possibly nested Variable objects
    """
    def feed(arr, node):
        step = -1
        item = []
        for token in node:
            step = (step + 1) % 4

            if step == 2:
                continue

            if step == 3 and not isinstance(token, basestring):
                feed(item, token)
            else:
                item.append(token)

            if step == 3:
                value = item[2:]
                if len(value) == 1:
                    value = value[0]

                arr.append(Variable(item[0], item[1], value))
                item = []

    arr = []
    feed(arr, get_grammar().parseString(text))
    return arr


def get_grammar():
    assign = Literal('=')
    lpar = Literal('{').suppress()
    rpar = Literal('}').suppress()
    vartype = Word(alphas + '_')
    varname = Word(alphas + nums + '._')
    varvalue = (Regex(r'0x[0-9a-fA-F]{2,}') | \
                Word(nums) | \
                QuotedString("\"\"\"", multiline=True))
    expr = Forward()
    atomic = vartype + varname + assign + varvalue
    struct = vartype + varname + assign + Group(lpar + expr + rpar)
    expr << ZeroOrMore(atomic | struct)
    return expr
