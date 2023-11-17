import idc
import idaapi
import idautils
from collections import defaultdict

# 这个脚本用来获取可执行文件中所有的偏移量以及对应使用这些偏移量的地址

displace = defaultdict(list)  # 用来保存偏移量以及使用这些偏移量的地址

for func in idautils.Functions():
    flags = idc.get_func_attr(func, idc.FUNCATTR_FLAGS)
    if flags & idc.FUNC_LIB or flags & idc.FUNC_THUNK:  # 分析的时候跳过库函数和thunk函数
        continue
    dism_addr = idautils.FuncItems(func)
    for line in dism_addr:
        op = None
        index = None

        # 解析当前的指令
        tmp_ins = idaapi.insn_t()
        idaapi.decode_insn(tmp_ins, line)
        if tmp_ins.Op1.type == idaapi.o_displ:  # 如果操作数是一个带有偏移量的内存引用
            op = 1
        if tmp_ins.Op2.type == idaapi.o_displ:
            op = 2
        if op is None:
            continue
        # 操作数中有bp寄存器的情况，例如mov eax, [ebp-0x4]，有bp寄存器的时候，偏移量是负数需要单独处理
        if "bp" in idc.print_operand(line, 0) or "bp" in idc.print_operand(line, 1):  # 如果操作数中有bp寄存器.n表示第n个操作数
            if op == 1:
                index = (~(int(tmp_ins.Op1.addr) - 1) & 0xFFFFFFFF)  # 获取偏移量
            else:
                index = (~(int(tmp_ins.Op2.addr) - 1) & 0xFFFFFFFF)  # tmp_ins.Op2.addr表示偏移量
        # 操作数中没有bp寄存器的情况，例如mov eax, [esp+0x4]
        else:
            if op == 1:
                index = int(tmp_ins.Op1.addr)
            else:
                index = int(tmp_ins.Op2.addr)

        if index:
            displace[index].append(hex(line))

print(displace)
