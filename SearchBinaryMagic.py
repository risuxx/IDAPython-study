import idc
import idaapi
import idautils

pattern = "74 32 FF"
# 搜索形式可以是 16 进制格式，比如 0x55 0x8B 0xEC和 55 8B EC 都是可以的，
# \x55\x8B\xEC 这种格式可不行，除非你使用 idc.find_text(ea, flag,y, x, searchstr)这个函数

addr = idc.get_inf_attr(idc.INF_MIN_EA)

for x in range(0, 5):
    # 这里只找5个满足条件的地址
    # 这里需要设置两个标记，一个是SEARCH_DOWN，表示从addr开始向下搜索，另一个是SEARCH_NEXT，表示从addr的下一个地址开始搜索
    # 假如不设置SEARCH_NEXT，那么搜索到的地址就是addr，但是不会再往下搜索了
    # SEARCH_UP 和 SEARCH_DOWN 用来指明搜索的方向
    # SEARCH_NEXT 用来获取下一个已经找到的对象
    # SEARCH_CASE 用来指明是否区分大小写
    # SEARCH_NOSHOW 用来指明是否显示搜索的进度
    addr = idc.find_binary(addr, idc.SEARCH_DOWN | idc.SEARCH_NEXT, pattern)
    if addr != idc.BADADDR:
        # 假如找到了就把他打印出来
        print(hex(addr), idc.GetDisasm(addr))
