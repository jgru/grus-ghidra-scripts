#!/usr/bin/env python3
import sys
import string
import re
import binascii
from unicorn import *
from unicorn.x86_const import *

STACK=0x90000
STACK_LEN = 4 * 4096
CODE_LEN = 0x100000
code_base = 0x10000000
mu = Uc(UC_ARCH_X86,UC_MODE_32)
data = open(sys.argv[1], 'rb').read()
matches = re.findall(b'''8d85..ffffffc7.+?8130..............4975f4''', binascii.hexlify(data))

mu.mem_map(code_base, 0x100000)
mu.mem_map(STACK, STACK_LEN)

for m in matches:
    try:
        blob = binascii.unhexlify(m)
    except:
        blob = binascii.unhexlify(m[1:])

    mu.mem_write(code_base, b'\x00' * CODE_LEN)
    mu.mem_write(STACK, b'\x00' * STACK_LEN)

    mu.mem_write(code_base, blob)
    mu.reg_write(UC_X86_REG_EBP, STACK+512)
    mu.reg_write(UC_X86_REG_ESP, STACK+1024)

    try:
        mu.emu_start(code_base, code_base + len(blob), timeout=10000)
    except Exception as e:
        print(e)
        pass

    stack_mem = mu.mem_read(STACK, STACK_LEN)

    # Split at double null-bytes, starting at the end
    # So that wchars are preserved in their original form

    candidates = stack_mem.rsplit(b'\x00\x00')
    for c in candidates:
        if c == b'':
            continue
        #c = b"\x00" + c
        try:
            if c[1] == 0:
                result = c.decode("UTF-16")
            else:
                result = c.decode("ASCII")
            print(result)

        except:
            pass
