import re
import sys
import string

def toStr(s):
    return s and chr(int(s[:2], base=16)) + toStr(s[2:]) or ''

rex = re.compile(r'"""([0-9a-fA-F]+)"""')
with open(sys.argv[1]) as f:
	for hs in rex.finditer(f.read()):
		print ''.join(filter(lambda x: x in string.printable, list(hs.group(1).decode('hex'))))
		#print ''.join(filter(lambda x: x in string.printable, map(lambda x: chr(int(x, 16)), list(hs.group(1)))))