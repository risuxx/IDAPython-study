import idc
import idaapi
import idautils

addr = idc.get_inf_attr(idc.INF_MIN_EA)
end = idc.get_inf_attr(idc.INF_MAX_EA)

while addr < end:
    # idc.find_text(ea, flag, y, x, searchstr) 这个函数用来搜索字符串，ea是搜索的起始地址，flag是搜索的标记，y和x是搜索的起始坐标，searchstr是要搜索的字符串
    # y, x 通常置为0
    addr = idc.find_text(addr, idc.SEARCH_DOWN, 0, 0, "accept")
    if addr == idc.BADADDR:
        break
    else:
        print(hex(addr), idc.GetDisasm(addr))
        # 这里不需要设置SEARCH_NEXT，因为这里手动将addr置为下一个地址了
        # idc.next_head(ea, maxea) 这个函数用来获取ea处的下一个地址，maxea是最大地址
        addr = idc.next_head(addr, end)
