import idc
import idaapi
import idautils

addr = idc.get_name_ea_simple("StartServiceCtrlDispatcherW")  # StartServiceCtrlDispatcherW是一个函数名，addr是这个函数的首地址
print(idc.GetDisasm(addr))  # 获取addr处的汇编指令

for i in idautils.CodeRefsTo(addr, 0):
    # idautils.CodeRefsTo(addr, flow)返回一个保存着所有调用addr的地址的数组, flow参数表示是否遵循正常的代码流。
    # 该函数的限制是，动态导入并手动重命名的API不会显示为代码交叉引用。
    print(hex(i), idc.GetDisasm(i))  # 获取addr处的汇编指令
