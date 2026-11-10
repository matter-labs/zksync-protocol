/* The guest's memory map, in place of riscv_common's 1 GiB `memory.x`. The host
   runs the machine with a 4 GiB RAM image (`RamSize::FourGb`); RAM stops 2 MiB
   short of 2^32 so that `_eheap`, which link.x aligns up to 2 MiB, stays a 32-bit
   address. ROM is unchanged: boot_sequence asserts `_estack == ROM_BYTE_SIZE`. */
MEMORY
{
  ROM (rx): ORIGIN = 0, LENGTH = 4M
  RAM (rwa!x) : ORIGIN = 4M, LENGTH = 4090M
}

REGION_ALIAS("REGION_TEXT", ROM);
REGION_ALIAS("REGION_DATAINIT", ROM);
REGION_ALIAS("REGION_RODATAINIT", ROM);
REGION_ALIAS("REGION_STACK", RAM);
REGION_ALIAS("REGION_DATA", RAM);
REGION_ALIAS("REGION_RODATA", RAM);
REGION_ALIAS("REGION_BSS", RAM);
REGION_ALIAS("REGION_HEAP", RAM);
