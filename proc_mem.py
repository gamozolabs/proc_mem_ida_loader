import re, subprocess, idaapi, ida_segment, ida_kernwin, os, ida_netnode
import ida_loader

# To install this, simply put it in your ida_install/loaders folder and open
# a `/proc/<pid>/mem` file!
#
# You might need to set `echo 1 > /proc/sys/kernel/yama/ptrace_scope` if you
# want to be able to dump processes depending on your system configuration.

def get_file_base(filename):
    # Try to get the `ImageBase` from `objdump`, this is used for PE files
    sp = b""
    try:
        sp = subprocess.check_output(["objdump", "-p", filename])
    except subprocess.CalledProcessError:
        pass

    mch = re.findall(rb"\nImageBase\s+([0-9a-f]+)\n", sp)
    if len(mch) != 1:
        # Try to get the `LOAD`ed section at offset 0 in the file to get
        # the image base for ELFs
        sp = b""
        try:
            sp = subprocess.check_output(["readelf", "-lW", filename])
        except subprocess.CalledProcessError:
            pass

        mch = re.findall(rb"\n\s+LOAD\s+0x0+\s+0x([0-9a-f]+)\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+[R ][W ][E ]\s+0x[0-9a-f]+\n", sp)
        if len(mch) != 1:
            # Okay we really couldn't find the base
            return None
        return int(mch[0], 16)

    return int(mch[0], 16)

# Check if the file is supported by our loader
def accept_file(li, filename):
    # Check if the filename is /proc/<pid>/mem, if so, we can handle it!
    mch = re.match("/proc/(\d+)/mem", filename)
    if not mch:
        return 0

    # We can handle this file!
    return {'format': f"{filename} dump", 'processor': 'metapc'}

# Load the file into the database!
def load_file(li, neflags, fmt):

    # Get the PID from the format
    pid = int(re.match("^/proc/(\d+)/mem dump$", fmt).group(1))

    # Ask the user about the bitness to use for segments
    bitness = ida_kernwin.ask_buttons(
        "64-bit", "32-bit", "Cancel", 0, "What bitness is this process?")
    if bitness == -1:
        # Cancelled
        return 0

    # Convert dialog selection to IDA's segment bitness values
    if bitness == 1:
        bitness = 2 # 64-bit
        idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT
    elif bitness == 0:
        bitness = 1 # 32-bit

    # List of (symbol filename, base address) to try to load as symbols once
    # the database is filled with bytes
    symbols = []

    # Open the maps file
    seg = idaapi.segment_t()
    with open(f"/proc/{pid}/maps") as fd:
        # Go through each line in the map
        for line in fd.readlines():
            # Parse the /proc/<pid>/maps line, super quality regex
            mch = re.match("([0-9a-f]+)-([0-9a-f]+) ([r-])([w-])([x-])[ps] ([0-9a-f]+) [0-9a-f]+:[0-9a-f]+ \d+\s+(.*)", line)
            start  = int(mch.group(1), 16)
            end    = int(mch.group(2), 16)
            r      = mch.group(3) == "r"
            w      = mch.group(4) == "w"
            x      = mch.group(5) == "x"
            offset = int(mch.group(6), 16)
            name   = mch.group(7)

            # If this segment is usable in any way, add it to the database
            if r or w or x:
                # Mark things as code if they're executable
                seg.start_ea = start
                seg.end_ea   = end
                seg.bitness  = bitness

                # Set up permissions
                seg.perm = 0
                if r:
                    seg.perm |= ida_segment.SEGPERM_READ
                if w:
                    seg.perm |= ida_segment.SEGPERM_WRITE
                if x:
                    seg.perm |= ida_segment.SEGPERM_EXEC

                # Add the segment!
                if x:
                    idaapi.add_segm_ex(seg, name, "CODE", 0)
                else:
                    idaapi.add_segm_ex(seg, name, "DATA", 0)

                # Set the bitness for this segment
                idaapi.set_segm_addressing(idaapi.getseg(start), bitness)

                # IDA's API doesn't like seeking negative
                if start >= 0x8000000000000000:
                    print(f"Unsupported address range {start:x}-{end:x} "
                           "leaving uninitialized")
                    continue

                # Seek to the data and read it
                li.seek(start)
                data = li.read(end - start)

                # It's possible we failed to read certain areas, so only
                # `put_bytes` if we actually got a valid result
                if data:
                    # Write in the bytes
                    idaapi.put_bytes(start, data)

                # If we found the mapping offset for the start of a file, then
                # record the filename and the location it was mapped so we can
                # try to apply symbols
                if offset == 0 and os.path.isfile(name):
                    symbols.append((name, start))

    # Apply symbols
    for (filename, actual_base) in symbols:
        # Get the original base of the file, we need to subtract this off as
        # IDA defaults to it
        orig_base = get_file_base(filename)

        # Make sure we got a base
        if orig_base != None:
            # Print some debug info about what we tried to do
            print(f"/proc/mem DWARF loader: file base: {orig_base:016x} "
                  f"loaded base: {actual_base:016x} {filename}")

            # Get the netnode for DWARF loading parameters
            node = ida_netnode.netnode("$ dwarf_params")

            # Set the filename of the DWARF to load
            node.supset(1, filename, 83)

            # Set the base to load the DWARF at. It defaults to the
            # original file base, so we subtract that off, and then compute
            # the actual base in the memory we dumped
            node.altset(2, -orig_base + actual_base, 65)

            if bitness == 2:
                # Invoke the DWARF64 plugin to load it!
                ida_loader.run_plugin(ida_loader.load_plugin("dwarf64"), 3)
            elif bitness == 1:
                # Invoke the DWARF32 plugin to load it!
                ida_loader.run_plugin(ida_loader.load_plugin("dwarf"), 3)
        else:
            # We cannot load symbols if we don't know the files original base
            print(f"/proc/mem DWARF loader: "
                  f"Couldn't load symbols for {filename}")

    # Loaded!
    return 1

