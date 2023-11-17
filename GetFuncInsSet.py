import idc
import idaapi
import idautils

# 这个函数可以获取当前光标所在的函数的所有指令
items = idautils.FuncItems(idc.here())
for item in items:
    print(hex(item), idc.GetDisasm(item))
