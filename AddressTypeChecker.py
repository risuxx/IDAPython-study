import idc
import idaapi
import idautils

addr = idc.here()
# idc.is_code(f)这个f不是地址，需要先通过idc.get_full_flags(addr)获取地址的内部标志表示，然后再传入
idc.is_code(idc.get_full_flags(addr))  # 判断addr处是否是代码
idc.is_data(idc.get_full_flags(addr))  # 判断addr处是否是数据
idc.is_unknown(idc.get_full_flags(addr))  # 判断addr处是否是未知数据
idc.is_head(idc.get_full_flags(addr))  # 判断addr处是否是头部
idc.is_tail(idc.get_full_flags(addr))  # 判断addr处是否是尾部
