#!/usr/bin/env python

import os
import sys, argparse
from struct import unpack
import re

## *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*

CHOICEPREFIX = {
    0x31: b'CHOICE-\x81\x9F',
    0x32: b'SWITCH-\x81\x9F',
}
SPECIALPREFIX = {
    #0x85: b'x85-\x81\x9F',
    0x86: b'x86-\x81\x9F',
}
RECORDSEP = b"\n\n"

def get_data_sjis(data, idx, end):
    result = b''
    while idx < end:
        tmp = data[idx:idx+1]
        if tmp == b'\x00':
            break
        result += tmp
        idx += 1
    return result

def escape_text(org):
    subs = org.split(b"\x0A")
    return b"{{newline}}".join(subs)

parser = argparse.ArgumentParser(description='Scan file to find shift-jis string')
parser.add_argument('-v', dest='verbose', help='show verbose output', action='store_true')
parser.add_argument('input', help='script file')
args = parser.parse_args()

outputpath = args.input + '-extr.txt'

## *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*

def getlen_opcode_X_plus_sz(data, start, extralen):
    str = get_data_sjis(data, start+1+extralen, start+500)
    return (1+extralen+len(str)+1, str)

def getlen_opcode_2_plus_sz(data, start):
    return getlen_opcode_X_plus_sz(data, start, 2)

def getlen_opcode_4_plus_sz(data, start):
    return getlen_opcode_X_plus_sz(data, start, 4)

def getlen_opcode_7_plus_sz(data, start):
    return getlen_opcode_X_plus_sz(data, start, 7)

def getlen_opcode05(data, start):
    first_byte = ord(data[start+1:start+2])
    if unpack("<H", data[start+2:start+4])[0] == 0xFFFF and unpack("<H", data[start+4:start+6])[0] == 0xFFFF:
        return (6, None)
    if first_byte == 0x2D and unpack("<H", data[start+2:start+4])[0] == 0x0006 and unpack("<H", data[start+4:start+6])[0] == 0:
        return (6, None)
    count = max(1, first_byte)
    return (count, None)

def getlen_opcode0E(data, start):
    count, = unpack("<H", data[start+3:start+5])
    return (5+6*count, None)

def getlen_opcodes_31_32(data, start):
    choices = []
    offsetstr = 7
    for i in range(ord(data[start+3:start+4])):
        choice = get_data_sjis(data, start+offsetstr+10, start+offsetstr+500)
        offsetstr += 10 + len(choice) + 1
        choices.append(choice)
    return (offsetstr, choices)


opcodeslen = {
    0x00: 1,
    0x01: 5, #?
    0x02: 5,
    0x03: 1, #?
    0x04: 5, #?
    0x05: 5, #?
    0x06: 9,
    0x07: 9, # for some reason sometimes followed by a 4-byte number 0x00012C33
    0x08: 9,
    0x09: 9,
    0x0A: 9,
    0x0B: 14,
    0x0C: 7,
    0x0D: 7,
    0x0E: getlen_opcode0E,
    0x0F: 9,
    
    0x10: 5,
    0x11: 5,
    0x12: 5,
    0x13: 5,
    0x14: 5,
    0x18: 5, #?
    0x19: 7, #?
    0x1A: 5,
    0x1B: 1,
    0x1C: 1,
    0x1D: 7,
    0x1E: 11,
    0x1F: 13,

    0x20: 7,
    0x21: 7,
    0x22: 5,
    0x23: 7,
    0x24: 7,
    0x25: 5,
    0x28: 3, #?
    #0x2A: ??, # see x360-147
    0x2C: 3,
    0x2D: 5,
    0x2E: 1,
    0x2F: 3,

    0x30: 11,
    0x31: getlen_opcodes_31_32, # choice
    0x32: getlen_opcodes_31_32,
    0x33: 1, #?
    0x34: 11,
    0x36: 4,
    0x39: 5,
    0x3A: 5,
    0x3B: 3,
    0x3C: 3,
    0x3D: 1,

    0x42: 9, #?
    0x43: 5,
    0x44: 6,
    0x45: getlen_opcode_4_plus_sz, # text
    0x47: getlen_opcode_2_plus_sz, # charname
    0x49: 5,
    0x4A: 3,
    0x4B: 5,
    0x4C: 7,
    0x4F: 5,

    0x5A: 1,
    0x5E: 3,
    0x5F: 1, #?

    0x62: 5,
    0x68: 11,
    0x69: 3,
    0x6A: 5,
    0x6C: 17,
    0x6E: 5,

    0x71: 7,
    0x72: 5,
    0x74: 7,
    0x75: 5,
    0x7B: 5,
    0x7C: 5,

    0x81: 3,
    0x82: 3,
    0x83: 5, # nullsub in x360
    0x85: getlen_opcode_4_plus_sz, # ? Debug string ?
    0x86: getlen_opcode_4_plus_sz, # ?
}

# x360 ver has an extra field for 0x47
if re.search('[xX]360', args.input) is not None:
    if args.verbose:
        print("x360 input detected based on filename")
    opcodeslen.update({
        0x05: getlen_opcode05,
        0x47: getlen_opcode_4_plus_sz,
        0x48: 3,
    })



## *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*

data = open(args.input, 'rb').read()
with open(outputpath, 'w', encoding='utf8', newline="\r\n") as resfile:
    entryidx = 1
    codeofs, = unpack('<L', data[0:0+4])
    
    length = len(data)
    while codeofs < length:
        if args.verbose:
            print("ofs {0:04X}".format(codeofs))
        opcode = data[codeofs]

        if opcode not in opcodeslen:
            print("ofs {0:04X} error {1:02X}".format(codeofs, opcode))
            break
        if hasattr(opcodeslen[opcode], '__call__'):
            try:
                oplen, opdata = opcodeslen[opcode](data, codeofs)
                if oplen <= 0 or oplen is None:
                    print("ofs {0:04X} error {1:02X} could not determine len={2}".format(codeofs, opcode, oplen))
                    break

                # [0x45] [<unk>.4B] [<serifu>.B0]
                # [0x47] [<unk>.2B] [<charname>.B0]
                # [0x86] [<unk>.4B] [<serifu>.B0]
                if opcode == 0x45 or opcode == 0x47 or opcode == 0x86:
                    rng = escape_text(opdata)
                    idxprefix = '<{0:03d}> '.format(entryidx).encode('utf-8')
                    rng = idxprefix + (SPECIALPREFIX[opcode] if opcode in SPECIALPREFIX else b'') + rng + RECORDSEP
                    sjistext = rng.decode('cp932')
                    entryidx = entryidx + 1
                    resfile.write(sjistext)
                # [0x31] [<unk>.2B] [<#choices>.4B?] #choices_times--([<>].10B [<text>.B0])--
                elif opcode == 0x31 or opcode == 0x32:
                    for choicetext in opdata:
                        choicerng = escape_text(choicetext)
                        idxprefix = '<{0:03d}> '.format(entryidx).encode('utf-8')
                        bintext = idxprefix + CHOICEPREFIX[opcode] + choicerng + RECORDSEP
                        choicetext = bintext.decode('cp932')
                        entryidx = entryidx + 1
                        resfile.write(choicetext)
                    
            except Exception as e:
                print("Unexpected error @{0:04X} - {1}: {2}".format(codeofs,sys.exc_info()[0], e), file=sys.stderr)
                print(opcodeslen[opcode])
                break
            
            codeofs += oplen
        else:
            codeofs += opcodeslen[opcode]

        if codeofs + 4 < length and opcode == 0x7 and unpack('<L', data[codeofs:codeofs+4])[0] == 0x00012C33:
            codeofs += 4

if os.path.getsize(outputpath) == 0:
    os.remove(outputpath)

