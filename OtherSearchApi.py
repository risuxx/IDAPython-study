import idc
import idaapi
import idautils

addr = idc.here()
# 寻找标志为代码的下一个地址，这对于查找数据块的末尾很有帮助
idc.find_code(addr, idc.SEARCH_DOWN | idc.SEARCH_NEXT)
idc.find_data(addr, idc.SEARCH_DOWN | idc.SEARCH_NEXT)
idc.find_unknown(addr, idc.SEARCH_DOWN | idc.SEARCH_NEXT)  # 用于查找IDA未识别为代码或数据的字节地址
idc.find_defined(addr, idc.SEARCH_DOWN | idc.SEARCH_NEXT)  # 用于查找IDA标识为代码或数据的字节地址
idc.find_imm(addr, idc.SEARCH_DOWN | idc.SEARCH_NEXT, 0x55)  # 用来寻找立即数
