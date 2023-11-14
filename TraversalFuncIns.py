import idc
import idaapi
import idautils

start = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)
end = idc.get_func_attr(idc.here(), idc.FUNCATTR_END)

cur_addr = start

while cur_addr < end:
    print(hex(cur_addr), idc.GetDisasm(cur_addr))
    cur_addr = idc.next_head(cur_addr, end)
