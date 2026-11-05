#!/usr/bin/env python3

import os
import re
import struct
import sys
import r2pipe

if len(sys.argv) < 2:
    print("usage: {} <upx-packed-binary>".format(sys.argv[0]))
    sys.exit(1)

filename=sys.argv[1]
dump_filename=filename+".dumped"

MAX_SYSCALL_WAITS = 20000  # safety valve: bail instead of spinning forever
                            # on a target that never issues the expected
                            # post-unpack munmap (e.g. not UPX-packed at all)

# r2 auto-names unknown mapped segments (e.g. "unk0"), but they're still
# attacker-influenced data flowing from a hostile sample into an r2 command
# string below -- keep only the characters a real r2 segment name uses so a
# crafted name can't smuggle extra ';'-separated commands into the session.
SAFE_NAME = re.compile(r'^[A-Za-z0-9_.:-]+$')

## load our file in debugger mode
print("loading "+filename)
r2 = r2pipe.open(filename, flags=['-2'])
r2.cmd('doo')

## get arch and bits info
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

## start syscall monitoring
## use ORAX (the pre-syscall RAX/EAX value, i.e. the syscall number) to
## figure out what syscall was just made -- EAX/RAX itself gets clobbered
## with the return value. Some r2 builds don't expose a separate 32-bit
## "oeax" alias, so just read orax and mask it -- the syscall number lives
## in the low 32 bits either way.
##
## Older UPX stubs unmap themselves (munmap) right before jumping to OEP --
## that's the classic signal this tool was originally written to catch.
## Newer UPX output (observed with UPX 4.2.4/amd64) instead does a direct
## tail jump straight into the decompressed payload without ever calling
## munmap, so also watch for control landing in a different mapped
## segment than the one we started in.
print("looking for post unpack breakpoint...")
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

    dm_res_probe = r2.cmdj('dmj')
    start_rip = int(r2.cmd('dr?rip'), 16)
    start_seg = segment_of(start_rip, dm_res_probe)
    for _step in range(MAX_STEPS_PER_BURST):
        r2.cmd('ds')
        rip = int(r2.cmd('dr?rip'), 16)
        seg = segment_of(rip, dm_res_probe)
        if seg is not None and start_seg is not None and seg['addr'] != start_seg['addr']:
            found_signal = True
            break
    if found_signal:
        break

if not found_signal:
    print("never observed a post-unpack munmap or cross-segment tail jump -- is this actually UPX-packed?")
    r2.quit()
    sys.exit(1)
print("found it!")

## KNOWN LIMITATION: the address we just landed at is NOT reliably the
## real entry point -- on UPX 4.2.4/amd64 it's an internal glue/trampoline
## a few thousand bytes before the binary's actual entry, confirmed by
## comparing against the unpacked binary's own readelf output. Ideally
## we'd run the debuggee forward to the real entry before dumping, but
## r2 6.0.5's `dc`/`dcu` continue-to-breakpoint did not reliably resume
## from wherever the single-step loop above left off in testing -- the
## debuggee ended up back at the stub's own tail-jump instruction instead
## of stopping at the requested breakpoint, and a slower workaround
## (polling for a clean ELF header after every syscall stop instead of
## single-stepping) was impractically slow. So this dump is captured at
## the tail-jump landing point -- the "unpacking is done" signal -- not
## at a state where execution has actually reached the real entry. It may
## still be missing some final relocation/finalization work the stub's
## own glue code would have done between here and the real entry.

## get memory map to identify segments
print("getting memory map...")
dm_res = r2.cmdj('dmj')

## patch existing elf headers to clean up 
## what will become incorrect sections info
print("patching ELF headers...")
base = r2.cmdj('dmj')[0]
r2.cmd('s '+str(hex(base['addr'])))
dump_headers = r2.cmdj('pfj.elf_header')
for elf_head in dump_headers:
    if elf_head['name'] == 'shnum':
        cmd = 'w0 1 @'+str(hex(elf_head['offset']))
        r2.cmd(cmd)
    elif elf_head['name'] == 'shstrndx':
        cmd = 'w0 1 @'+str(hex(elf_head['offset']))
        r2.cmd(cmd)
    elif elf_head['name'] == 'shoff':
        cmd = 'w0 8 @'+str(hex(elf_head['offset']))
        r2.cmd(cmd)

## dump the segments to disk
print("extracting mem segments...")
dump_names = []
dump_segs = []
for seg in dm_res:
    if seg['name'].find('unk') != -1:
        if seg['perm'].find('---') == -1:
            if not SAFE_NAME.match(seg['name']):
                print("skipping segment with unexpected name: "+repr(seg['name']))
                continue
            seg_len = seg['addr_end']-seg['addr']
            seg_name = "seg_"+seg['name']
            dump_cmd = "wtf "+seg_name+" "+str(hex(seg_len))+" @ "+str(hex(seg['addr']))
            r2.cmd(dump_cmd)
            dump_names.append(seg_name)
            dump_segs.append(seg)
            print(seg_name+" extracted...")


def patch_program_header_offsets(raw, included):
    """The ELF header/phdr table we captured came straight out of the live
    process, so every PT_LOAD's p_offset still points at that offset in the
    *original on-disk file* -- meaningless for this brand new dump, whose
    segments are laid out differently. Walk the phdr table and rewrite each
    PT_LOAD's p_offset to where its data actually landed in `raw`, using
    `included` (the (segment, new_file_start_offset) pairs) to translate a
    segment's original runtime vaddr range into its new file position.
    Without this the kernel maps the wrong file bytes at load time and the
    dump segfaults instead of running.
    """
    raw = bytearray(raw)
    if len(raw) < 0x40 or raw[:4] != b"\x7fELF":
        print("warning: dump doesn't start with a clean ELF header -- skipping phdr fixup")
        return bytes(raw)

    ei_class = raw[4]
    if ei_class == 2:      # ELFCLASS64
        e_phoff, = struct.unpack_from('<Q', raw, 0x20)
        e_phentsize, = struct.unpack_from('<H', raw, 0x36)
        e_phnum, = struct.unpack_from('<H', raw, 0x38)
        phdr_fmt = '<IIQQQQQQ'  # type, flags, offset, vaddr, paddr, filesz, memsz, align
        OFF_IDX, VADDR_IDX = 2, 3
    elif ei_class == 1:    # ELFCLASS32
        e_phoff, = struct.unpack_from('<I', raw, 0x1C)
        e_phentsize, = struct.unpack_from('<H', raw, 0x2A)
        e_phnum, = struct.unpack_from('<H', raw, 0x2C)
        phdr_fmt = '<IIIIIIII'  # type, offset, vaddr, paddr, filesz, memsz, flags, align
        OFF_IDX, VADDR_IDX = 1, 2
    else:
        print("warning: unrecognized ELF class -- skipping phdr fixup")
        return bytes(raw)

    PT_LOAD = 1
    entry_size = struct.calcsize(phdr_fmt)
    for i in range(e_phnum):
        entry_off = e_phoff + i * e_phentsize
        if entry_off + entry_size > len(raw):
            continue
        fields = list(struct.unpack_from(phdr_fmt, raw, entry_off))
        if fields[0] != PT_LOAD:
            continue
        p_vaddr = fields[VADDR_IDX]
        new_offset = None
        for seg, start in included:
            if seg['addr'] <= p_vaddr < seg['addr_end']:
                new_offset = start + (p_vaddr - seg['addr'])
                break
        if new_offset is None:
            print("warning: couldn't relocate PT_LOAD @ vaddr "+hex(p_vaddr)+
                  " to a captured segment -- leaving its offset unpatched")
            continue
        fields[OFF_IDX] = new_offset
        struct.pack_into(phdr_fmt, raw, entry_off, *fields)

    return bytes(raw)


## reconstruct our unpacked ELF file
## using the extracted segments
## test for ELF minus UPX! headers and
## skip segments until you find a clean
## ELF header... also clean up
print("generating dumped ELF...")
kept = []  # (seg, data) pairs that make it into the final dump, in order
elf_found = False
for seg_name, seg in zip(dump_names, dump_segs):
    seg_file = open(seg_name,"r+b")
    seg_data = seg_file.read()
    seg_file.close()
    os.remove(seg_name)
    if elf_found == False:
        if seg_data[1:4] == b"ELF":
            if seg_data.find(b"UPX!") != -1:
                continue
            elf_found = True
        else:
            continue
    kept.append((seg, seg_data))

offsets = []
cum = 0
for seg, data in kept:
    offsets.append((seg, cum))
    cum += len(data)
raw = b"".join(data for _, data in kept)
raw = patch_program_header_offsets(raw, offsets)

dumped = open(dump_filename,"w+b")
dumped.write(raw)

## done, close our dump file and inform user
dumped.close()
print("dumped binary written to: "+dump_filename)
r2.quit()
