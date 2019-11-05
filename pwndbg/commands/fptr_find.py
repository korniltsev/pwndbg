#!/usr/bin/env python
# -*- coding: utf-8 -*-


from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
from queue import *

import gdb

import pwndbg.color.chain as C
import pwndbg.color.memory as M
import pwndbg.color.message as message
import pwndbg.color.theme as theme
import pwndbg.commands
import pwndbg.vmmap
from pwndbg.chain import config_arrow_right

import subprocess


parser = argparse.ArgumentParser()
parser.add_argument("-s", "--spoil", type=str, nargs="?", default="False", help="")
parser.add_argument("-a", "--avoid", type=str, nargs="?", default="[stack],[vdso],[vsyscall]", help="")

parser.description = """
"""
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def fptr_find(spoil, avoid):
    print(spoil, avoid)
    spoil = spoil == "true" or spoil == "True"
    skip = avoid.split(",") # ['[stack]', '[vdso]', '[vsyscall]']
    step = 8 # todo if step is 1, spoil may overlap
    psize = 8
    # spoil = True
    pages = list(pwndbg.vmmap.get())
    rw =    list(filter(lambda p: p.rw      and p.objfile not in skip, pwndbg.vmmap.get()))
    rx =    list(filter(lambda p: p.execute and p.objfile not in skip, pwndbg.vmmap.get()))

    fptrs = []
    for i in rw:
        for it in range(i.start, i.end, step):
            # print(hex(it))
            try:
                ptr = int(pwndbg.memory.pvoid(it))
                for j in rx:
                    if ptr in j:      
                        fptrs += [(it, ptr)]
            except gdb.error:
                p1 = pwndbg.vmmap.find(it)
                p2 = pwndbg.vmmap.find(it + psize-1)
                if p1 is not None and p2 is None:
                    pass
                else:
                    print("fucked up", hex(it))

    print(len(fptrs), "total")

    cmd = ["cyclic", str(len(fptrs) * psize)]
    cyclic = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    for i in range(len(fptrs)):
        it = fptrs[i]
        replacement = cyclic[i*psize:i*psize + psize]
        if spoil:
            print(hex(it[0]), " -> ", hex(it[1]),  " => ", replacement)
            pwndbg.memory.write(it[0], replacement)
        else:
            print(hex(it[0]), " -> ", hex(it[1]))

            
