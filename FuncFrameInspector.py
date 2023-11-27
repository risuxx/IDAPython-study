import idc
import idaapi
import idautils

addr = idc.here()

func = idaapi.get_func(addr)
frame = idaapi.get_frame(func)

print(frame)

x = 0
dictMem = {}

while x < frame.memqty:
    name = idc.get_member_name(frame.id, frame.get_member(x).soff)  # soff表示结构体成员的偏移量
    dictMem[name] = hex(idc.get_member_offset(frame.id, name))
    x += 1

# 注意此偏移都是相对于当前栈帧的栈底(也就是esp)来说的。注意两个非常重要的成员” r”和” s”，其中” r”代表返回地址存储的偏移，
# ” s”代表当前函数栈帧中ebp距离esp的位置(也就是函数栈帧的大小)。注意有个空格
print(dictMem)
