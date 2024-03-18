import idc
import idaapi
import idautils

# 正则搜索特征值
import re
pattern = "74 03 75 01 E8"


addr = idc.get_inf_attr(idc.INF_MIN_EA)
for x in range(0, 10):
    addr = idc.find_binary(addr, idc.SEARCH_DOWN | idc.SEARCH_NEXT, pattern)
    if addr != idc.BADADDR:
        # 假如找到了就把他打印出来
        print(hex(addr), idc.GetDisasm(addr))
        # 把这个地址patch成nop
        idc.patch_dword(addr, 0x90909090)
        idc.patch_byte(addr + 4, 0x90)

