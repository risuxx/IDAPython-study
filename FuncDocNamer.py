import idc
import idaapi
import idautils

# 演示idapython的注释和重命名功能
# 添加注释，也就是常规注释
addr = idc.here()
idc.set_cmt(addr, "This is a comment", 0)
# 增加重复性注释，重复性注释会因为某些地址引用了当前地址的内容，而自动添加到引用地址的注释中
addr = idc.next_head(addr, idc.get_inf_attr(idc.INF_MAX_EA))
idc.set_cmt(addr, "This is a repeatable comment", 1)

# 不仅仅指令可以添加注释，对于函数也可以添加注释
# 这里选择添加重复性注释，也就是每次引用函数的时候都会添加注释
# 获取当前地址所在的函数的地址
func_addr = idc.get_func_attr(addr, idc.FUNCATTR_START)
idc.set_func_cmt(func_addr, "This is a function comment", 1)

# 对函数重命名
idc.set_name(func_addr, "MyFunc", idc.SN_CHECK)

# 值得注意的是 rename_wrapper 中的 idc.MakeNameEx(ea,name, flag)用法，因为使用 idc.MakeName 的话，如果某一个函数名称已经被使用了，
# 那么ida 会抛出一个警告的对话。为了跳过该对话框，我们将 flag 的值设置为 256 或者SN_NOWARN 即可。我们可以应用一些逻辑来将函数重命名为 w_HeapFree_1 等，
# 但为简洁起见，我们会将其忽略。
