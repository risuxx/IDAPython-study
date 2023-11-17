import idc
import idaapi
import idautils

# 获取进行动态调用的函数的地址，例如call eax， jmp edi等
# 有些加壳的代码逻辑会使用这种方式进行函数调用，这种方式的函数调用是动态的
for func in idautils.Functions():
    flags = idc.get_func_attr(func, idc.FUNCATTR_FLAGS)
    if flags & idc.FUNC_LIB or flags & idc.FUNC_THUNK:  # 分析的时候跳过库函数和thunk函数
        continue
    dism_addr = idautils.FuncItems(func)
    for line in dism_addr:
        ins_mnem = idc.print_insn_mnem(line)  # 获取指令的助记符
        if ins_mnem == "call" or ins_mnem == "jmp":
            op = idc.get_operand_type(line, 0)  # 获取操作数的类型
            if op == idc.o_reg:  # 如果是寄存器类型的操作数
                print(hex(line), idc.GetDisasm(line))
