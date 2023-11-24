import idc
import idaapi
import idautils

# 可以使用如下的api来获取原始数据
addr = idc.here()
idc.get_wide_byte(addr)  # 获取一个字节
idc.get_wide_word(addr)  # 获取一个字
idc.get_wide_dword(addr)  # 获取一个双字
idc.get_qword(addr)  # 获取一个四字
idc.GetFloat(addr)  # 获取一个浮点数
idc.GetDouble(addr)  # 获取一个双精度浮点数

# 还可以获取更多的字节
idc.get_bytes(addr, 4, use_dbg=False)  # 获取4个字节, 最后的参数是可选的表示 use debugger memory or just the database
