import idc
import idaapi
import idautils

for func in idautils.Functions():
    flags = idc.get_func_attr(func, idc.FUNCATTR_FLAGS)
    if flags & idc.FUNC_NORET:
        # 表示函数没有返回值
        print(hex(func), "noreturn")
    if flags & idc.FUNC_FAR:
        # 表示函数是否使用分段内存，这个标签比较少见
        print(hex(func), "far")
    if flags & idc.FUNC_LIB:
        # 表示函数是否是库函数，我们一般判断出是库函数就在分析的时候跳过
        print(hex(func), "library")
    if flags & idc.FUNC_STATIC:
        # 表示函数是否是静态函数，被定义为静态函数那么就只能被本文件中的函数访问
        print(hex(func), "static")
    if flags & idc.FUNC_FRAME:
        # 表示函数是否使用了栈帧，也就是ebp寄存器
        print(hex(func), "frame")
    if flags & idc.FUNC_HIDDEN:
        # 表示他们是隐藏的需要展开才能查看啊，可以显示或隐藏反汇编代码
        print(hex(func), "hidden")
    if flags & idc.FUNC_THUNK:
        # 表示是否是一个thunk函数，thunk函数是一个跳板函数，他们的作用是调用另一个函数
        print(hex(func), "thunk")
    if flags & idc.FUNC_BOTTOMBP:
        # 用于识别是否使用了栈帧
        print(hex(func), "bottombp")
    if flags & idc.FUNC_NORET_PENDING:
        # Function 'non-return' analysis
        # must be performed. This flag is
        # verified upon func_does_return()
        print(hex(func), "noretpending")
    if flags & idc.FUNC_SP_READY:
        # 已经执行了SP分析。如果该标志位打开，堆栈变化点将不再被修改。目前，该分析仅针对PC执行。
        print(hex(func), "spready")
    if flags & idc.FUNC_PURGED_OK:
        # "argsize"字段已经通过验证。如果该位清零且'argsize'为0，则表示我们不知道从堆栈中真
        # 正移除的字节数。这个位由处理器模块处理。
        print(hex(func), "purgedok")
    if flags & idc.FUNC_TAIL:
        # 表示函数是否是尾调用函数，尾调用函数是指一个函数的最后一条指令是调用另一个函数
        print(hex(func), "tail")
