#!/usr/bin/python3
import sys
import json
import xmltodict

s = open(sys.argv[1]).read()
d = xmltodict.parse(s)
json.dump(d, open(sys.argv[2],'w'))
