# Summary

This IDA loader can snapshot a running 32-bit or 64-bit Linux process, as well
as 32-bit and 64-bit WINE processes on Linux, load it into IDA with the
actual processes memory permissions, and then apply DWARF symbols using IDA's
built-in DWARF loader for each loaded binary (that has DWARF symbols)!

This is a small IDA loader script (copy `proc_mem.py` into your `ida/loaders`
folder) and then open a `/proc/<pid>/mem` file in IDA!

This will automatically find all memory regions in the process, create segments
for them with the correct permissions, and apply symbols to them!

This works for both 32-bit and 64-bit Linux processes. It also works with WINE
binaries that have 32 or 64-bit PE files (with DWARF symbols).

# How does it work?

Simple, it dumps `/proc/<pid>/maps` to get the listing of memory regions for
the process, parses them with regex. This gives us the state of the programs
address space and permissions. As well as tells us if it's a mapped file. We
read the bytes from `/proc/<pid>/mem` and then initialize the segment with that
data.

Then, for all memory regions which are mapped from a file, if that file is
mapped at offset 0 (eg. the `\x7fELF` or `MZ` headers are mapped at this
location), we will attempt to load it as a DWARF symbol file using IDA's
built-in DWARF symbol loader.

IDA's DWARF loader plugin isn't documented, but I reversed it out and found
that by calling `run_plugin` with argument `3` you can pass in a filename and
an offset. Thus, we use the original IDA DWARF loader and hopefully should get
all the approprate info you would get if you loaded files individually!

