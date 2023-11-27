import idc
import idaapi
import idautils

debugger = idaapi.DBG_Hooks()
debugger.hook()
# 这样设置后hook会捕捉所有的调试事件，下面的函数再调试的时候会比较有用。

# idc.add_bpt( long Address ) # 在指定的地点设置软件断点。
# idc.get_bpt_qty() #返回当前设置的断点数量。
# idc.get_reg_value(string Register) # 获取寄存器的值 ,dbg必须处于运行状态
# idc.set_reg_Value(long Value, string Register) # 通过寄存器名获得寄存器值。
