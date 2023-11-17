import idc
import idaapi
import idautils

# 获取程序的地址空间
min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
max_ea = idc.get_inf_attr(idc.INF_MAX_EA)

# 遍历函数
for func in idautils.Functions():
    flags = idc.get_func_attr(func, idc.FUNCATTR_FLAGS)
    if flags & idc.FUNC_LIB or flags & idc.FUNC_THUNK:
        continue
    dism_addr = list(idautils.FuncItems(func))

    for cur_addr in dism_addr:
        if idc.get_operand_type(cur_addr, 0) == idc.o_imm and (min < idc.get_operand_value(cur_addr, 0) < max):
            idc.op_plain_offset(cur_addr, 0, 0)  # 将操作数转换为偏移量
            print(hex(cur_addr), idc.GetDisasm(cur_addr))
        if idc.get_operand_type(cur_addr, 1) == idc.o_imm and (min < idc.get_operand_value(cur_addr, 1) < max):
            idc.op_plain_offset(cur_addr, 1, 0)  # 将操作数转换为偏移量
            # idc.op_plain_offset可以将操作数转换为偏移量，第一个参数为地址，第二个参数为操作数的序号，第三个参数是及地址。
            # 示例:
            #  seg000:2000 dw      1234h
            # and there is a segment at paragraph 0x1000 and there is a data item
            # within the segment at 0x1234:
            #  seg000:1234 MyString        db 'Hello, world!', 0
            # Then you need to specify a linear address of the segment base to
            # create a proper offset:
            #      op_plain_offset(to_ea("seg000", 0x2000), 0, 0x10000);
            # and you will have:
            #  seg000:2000 dw      offset MyString
            # 从1234h变成了offset MyString
            print(hex(cur_addr), idc.GetDisasm(cur_addr))
