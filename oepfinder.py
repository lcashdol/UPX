#!/usr/bin/env python3

import os
import sys
import r2pipe

if len(sys.argv) < 2:
    print("usage: {} <upx-packed-binary>".format(sys.argv[0]))
    sys.exit(1)

filename = sys.argv[1]
coredump = filename+'.coredump'

MAX_SYSCALL_WAITS = 20000  # safety valve: bail instead of spinning forever
                            # on a target that never issues the expected
                            # post-unpack munmap (e.g. not UPX-packed at all)

## load our file and get it setup for debugging
r2 = r2pipe.open(filename, flags=['-2'])
r2.cmd('doo')

## extract arch and bits info
## radare2 >= 6.x nests this under "bins" (a list, one per sub-binary)
## instead of the old flat "info" key -- handle both so this still works
## against whatever r2 the user has installed.
iaj = r2.cmdj('iaj')
binfo = iaj['bins'][0] if 'bins' in iaj else iaj['info']
arch = binfo['arch']
bits = binfo['bits']

if arch != "x86":
    print("arch is not supported :*(")
    r2.quit()
    sys.exit(1)
else:
    if bits == 64:
        arch = "x86_64"

def segment_of(addr, segs):
    for seg in segs:
        if seg['addr'] <= addr < seg['addr_end']:
            return seg
    return None


MAX_STEPS_PER_BURST = 400  # how far to single-step looking for a cross-segment
                            # jmp/call before going back to waiting on syscalls

## Older UPX stubs unmap themselves (munmap) right before jumping to OEP --
## that's the classic signal this tool was originally written to catch.
## Newer UPX output (observed with UPX 4.2.4/amd64) instead does a direct
## tail jump straight into the decompressed payload without ever calling
## munmap. So: after every syscall stop, also single-step a bounded
## distance forward watching for control landing in a different mapped
## segment than the one we started in -- that catches both styles.
##
## Important: the address we land at here is NOT reliably the real OEP.
## On UPX 4.2.4/amd64 the tail jump lands on an internal glue/trampoline
## address inside the decompressed image, a few thousand bytes before the
## binary's actual entry point -- confirmed by comparing against the
## unpacked binary's own ELF header. So treat this only as a "the stub is
## done, the clean payload is now in memory" signal, then go read the
## payload's own embedded ELF header for its real `entry` field, and run
## forward to a breakpoint there. That's correct regardless of how many
## internal hops the stub takes to get there.
found_signal = False
for _ in range(MAX_SYSCALL_WAITS):
    syscall = r2.cmd('dcs')
    syscall_val = int(r2.cmd('dr?orax'), 16) & 0xffffffff
    if arch == "x86" and syscall_val == 91:
        found_signal = True
        break
    elif arch == "x86_64" and syscall_val == 11:
        found_signal = True
        break

    dm_res = r2.cmdj('dmj')
    start_rip = int(r2.cmd('dr?rip'), 16)
    start_seg = segment_of(start_rip, dm_res)
    for _step in range(MAX_STEPS_PER_BURST):
        r2.cmd('ds')
        rip = int(r2.cmd('dr?rip'), 16)
        seg = segment_of(rip, dm_res)
        if seg is not None and start_seg is not None and seg['addr'] != start_seg['addr']:
            found_signal = True
            break
    if found_signal:
        break

if not found_signal:
    print("never observed a post-unpack munmap or cross-segment tail jump -- is this actually UPX-packed?")
    r2.quit()
    sys.exit(1)

## find the clean (non-UPX-tagged) ELF header now sitting in memory
dm_res = r2.cmdj('dmj')
found_elf = False
for seg in dm_res:
    r2.cmd('s '+str(hex(seg['addr'])))
    elf_hit = r2.cmd('/ ELF')
    upx_hit = r2.cmd('/ UPX!')
    if len(elf_hit) > 0:
        if len(upx_hit) == 0:
            found_elf = True
            break

if not found_elf:
    print("couldn't find a clean (non-UPX-tagged) ELF header in any mapped segment")
    r2.quit()
    sys.exit(1)

## read its real entry point, then run forward to a breakpoint there --
## this is the actual "fully unpacked, about to execute" point, however
## many internal glue/trampoline hops the stub takes to reach it
elf_headers = r2.cmdj('pfj.elf_header')
real_entry = None
for elfhdr in elf_headers:
    if elfhdr['name'] == 'entry':
        real_entry = elfhdr['value']
        break

if real_entry is None:
    print("couldn't read the real entry point from the clean ELF header")
    r2.quit()
    sys.exit(1)

OEP = hex(real_entry)
r2.cmd('db '+OEP)
r2.cmd('dc')
r2.cmd('db -'+OEP)
rip_now = int(r2.cmd('dr?rip'), 16)
if rip_now != real_entry:
    print("warning: never actually reached the real entry point "+OEP+
          " (stopped at "+hex(rip_now)+" instead) -- OEP below may be unreliable")

## seek to OEP and grab 25 diasm instructions
r2.cmd('s '+OEP)
ent_inst = r2.cmdj('pdj 25')

## for 32 bit we'll be looking for hlt & call
## before we look for our push to do this
## we'll consume the instructions backwards
## for 64bit the match is strong without needing
## context so just search for the mov into RDI
ent_inst.reverse()
hlt = False
call = False
main_addr = None
for inst in ent_inst:
    if inst['disasm'].find('hlt') != -1:
        hlt = True
        continue
    if hlt == True and inst['disasm'].find('call') != -1:
        call = True
        continue
    if hlt == True and call == True:
        if arch == "x86":
            if inst['disasm'].find('push 0x') != -1:
                main_addr = inst['disasm'].split(' ')[1].strip()
                break
        elif arch == "x86_64":
            if inst['disasm'].find('mov rdi, 0x') != -1:
                main_addr = inst['disasm'].split(',')[1].strip()
                break

## generate our coredump and produce findings
r2.cmd('dg '+coredump)

print("\n============\n")
print('coredump written to: ')
print(coredump)
print("\nfunc addresses:")
print('OEP @ '+OEP)
if main_addr is None:
    print("main @ <not found -- entry prologue didn't match the expected hlt/call/push pattern>")
else:
    print('main @ '+main_addr)
print("\n============\n")

r2.quit()
