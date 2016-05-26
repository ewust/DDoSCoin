#!/usr/bin/python

import sys
import hashlib
import time


f = open(sys.argv[1], 'rb')
data = f.read()
f.close()

CREATION_STR = 'CreationDate (D:'
MOD_STR = 'ModDate (D:'
c_index = data.index(CREATION_STR) + len(CREATION_STR)
m_index = data.index(MOD_STR) + len(MOD_STR)

c_index_end = c_index + 14  # 20160401001122
m_index_end = m_index + 14

if (m_index < c_index):
    print 'Weird order of indexes...aborting'
    sys.exit(1)

t = int(time.time())
n = 0
while True:
    t += 1
    n += 1

    date_str = time.strftime('%Y%m%d%H%M%S', time.localtime(t))
    new_data = data[0:c_index] + date_str + \
                data[c_index_end:m_index] + \
                date_str + \
                data[m_index_end:]

    h = hashlib.sha1(new_data).hexdigest()
    print t, h
    if h[0:3] == '666':
        print 'Found after %d iterations, %s' % (n, time.strftime('%Y-%m-%d-%H:%M:%S', time.localtime(t)))
        f = open(sys.argv[1], 'wb')
        f.write(new_data)
        f.close()
        sys.exit(0)
