/*
 * Linker script for neutrino-default-runtime (rv32im-unknown-none-elf).
 *
 * Memory layout (matches the runtime-host's default loader window):
 *
 *   ROM  0x00010000 .. 0x00020000  (64 KiB)  text + rodata, RX
 *   RAM  0x00020000 .. 0x00040000  (128 KiB) data + bss + stack, RW
 *
 * `_stack_top` lives at the top of the RAM region. The stack grows
 * downward; we reserve 16 KiB up front and let the host trap any
 * overflow as a MemoryFault.
 */

MEMORY
{
    ROM (rx) : ORIGIN = 0x00010000, LENGTH = 64K
    RAM (rw) : ORIGIN = 0x00020000, LENGTH = 128K
}

ENTRY(_start)

SECTIONS
{
    .text :
    {
        KEEP(*(.text.init))
        *(.text .text.*)
        . = ALIGN(4);
    } > ROM

    .rodata :
    {
        *(.rodata .rodata.*)
        . = ALIGN(4);
    } > ROM

    .data :
    {
        *(.data .data.*)
        . = ALIGN(4);
    } > RAM

    .bss :
    {
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        _bss_end = .;
        /* Reserve 16 KiB of stack space and pin `_stack_top` at the
           top of it. The stack lives inside .bss so the segment's
           memsz covers it; the ELF loader zero-fills the whole range.
           Anything beyond `_stack_top` is unmapped and traps. */
        . = . + 16K;
        . = ALIGN(16);
        _stack_top = .;
    } > RAM

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
        *(.riscv.attributes)
        *(.gnu.attributes)
    }
}
