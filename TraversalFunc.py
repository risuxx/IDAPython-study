import idc
import idaapi
import idautils

# Funcitons()返回一个保存着已知函数首地址的数组，同样这个函数也可可以用来朝朝指定范围内的函数
# get_func_name(ea) 用来获取函数名，ea这个参数可以是处于函数中的任何地址
# idaapi.get_func_qty() 用来获取函数的数量
# idaapi.getn_func(idx) 用来获取第idx个函数的首地址

for func in idautils.Functions():
    print(func, idc.get_func_name(func))
    # 获取函数的边界信息
    func_obj = idaapi.get_func(func)
    print(hex(func_obj.start_ea), hex(func_obj.end_ea))
    # 可以通过idc.get_next_func(ea)来获取下一个函数的首地址，通过idc.get_prev_func(ea)来
    # 获取上一个函数的首地址,但是ea需要在函数的范围内
    # 可以使用另一个api来获取函数的边界信息
    print(idc.get_func_attr(func, idc.FUNCATTR_START), idc.get_func_attr(func, idc.FUNCATTR_END))
    # 根据函数名获取函数地址
    print(hex(idc.get_name_ea_simple(idc.get_func_name(func))))

