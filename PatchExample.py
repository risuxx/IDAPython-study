import idc
import idaapi
import idautils

addr = idc.here()
idc.patch_byte(addr, 0x90)  # patch a byte
idc.patch_word(addr, 0x9090)  # patch a word
idc.patch_dword(addr, 0x90909090)  # patch a dword
idc.patch_qword(addr, 0x9090909090909090)  # patch a qword
