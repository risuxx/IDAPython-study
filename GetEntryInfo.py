import idc
import idaapi
import idautils

idc.get_entry_qty()  # 获取入口点数量
ordinal = idc.get_entry_ordinal(0)  # 获取入口点序号, 0表示第一个入口点
idc.get_entry_name(ordinal)  # 获取入口点名称，ordinal表示入口点序号
