import idc
import idaapi
import idautils

# 获取高亮选中部分的起始地址和结束地址
start = idc.read_selection_start()
end = idc.read_selection_end()
print(hex(start), hex(end))

# 上面的代码可以使用idaapi.read_selection()来代替
p0 = idaapi.twinpos_t()
p1 = idaapi.twinpos_t()
view = idaapi.get_current_viewer()
selected = idaapi.read_selection(view, p0, p1)
if selected:
    print(hex(p0.place(view).toea()), hex(p1.place(view).toea()))
# 最终打印结果会有略微差别，这是因为idc.read_selection_end()获取的并不是这一段代码的末尾地址，而是这一段代码的下一条指令的起始地址
# 0x42e080 0x42e0c0
# 0x42e080 0x42e0b1
# https://gist.github.com/bNull/6003874 这个脚本是这个功能的应用，它提供新的快捷键用来转化高亮代码块的形式
