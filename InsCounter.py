# coding:utf-8

import idc
import idaapi
import idautils

# 该脚本用于统计idb中包含多少行命令
# 使用方法：在命令行中输入 idat.exe -A -S"InsCounter.py" xxx.idb
# 其中xxx.idb为ida数据库文件，-A表示自动分析，-S表示idb被打开之后立即执行的脚本，InsCounter.py为脚本文件名
# 假如要在脚本中使用参数，则可以使用 idat.exe -A -S"InsCounter.py test" xxx.idb ，这个参数可以使用idc.ARGV获取

# 该脚本为命令行中可执行的脚本
idaapi.auto_wait()  # 自动等待，等待ida加载完毕，ida必须加载完毕之后再进行脚本的分析，不然会出现问题

count = 0

for func in idautils.Functions():
    flags = idc.get_func_attr(func, idc.FUNCATTR_FLAGS)
    if flags & idc.FUNC_LIB:  # 跳过库函数
        continue
    for inst in idautils.FuncItems(func):
        count += 1

f = open("ins_count.txt", "w")

writeContent = f"Total instructions count: {count}"

print(writeContent)
f.write(writeContent)
f.close()
idc.qexit(0)  # 退出脚本
