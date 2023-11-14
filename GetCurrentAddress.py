import idc
import idaapi
import idautils

# 这两个都可以获取当前光标所在的地址
print(idc.here())
print(idc.get_screen_ea())
