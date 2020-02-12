# Updates error codes in ccp_error.h

import sys

count = 0
section = 0
section_size = 10

lines = []

with open('ccp_error.h') as f:
    for l in f:
        l = l.strip().split(" ")
        if l and len(l) > 1:
            if l[0] == "#define" and l[1] != "OK":
                val = - (section * section_size + count)
                l[2] = str(val)
                count += 1
            if l[0] == "//":
                section += 1
                count = 1
        lines.append(" ".join(l))

with open('ccp_error.h', 'w') as f:
    for line in lines:
        f.write(line + "\n")
