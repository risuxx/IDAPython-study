import idc
from idc import *
import ida_nalt

module_data_addr = 0x05289C0
pcHeader_addr = idc.get_qword(module_data_addr)

if idc.get_wide_dword(pcHeader_addr) != 0x0FFFFFFF0:
    print(idc.get_wide_dword(pcHeader_addr))
    print("错误，并不是一个正确的go文件")

funcnametab_addr = idc.get_qword(module_data_addr + 8)
filetab_addr = idc.get_qword(module_data_addr + 8 + ((8*3) * 2))
pclntable_addr = idc.get_qword(module_data_addr + 8 + ((8*3) * 4))
pclntable_size = idc.get_qword(module_data_addr + 8 + ((8*3) * 4) + (8 * 4))
set_name(module_data_addr, "firstmoduledata")
set_name(funcnametab_addr, "funcnametable")
set_name(filetab_addr, "filetab")
set_name(pclntable_addr, "pclntable")

print(pclntable_size)


def read_string(addr):
    ea = addr

    res = ''
    cur_ea_db = get_db_byte(ea)
    while  cur_ea_db != 0 and cur_ea_db != 0xff:
        res += chr(cur_ea_db)
        ea += 1
        cur_ea_db = get_db_byte(ea)
    return res


def convert_ida_supported_string(name):
    # 将函数名称改成ida 支持的字符串
    #print(name)
    if type(name) != str:
        name = name.decode()
    name = name.replace('.', '_').replace("<-", '_chan_left_').replace('*', '_ptr_').replace('-', '_').replace(';','').replace('"', '').replace('\\', '')
    name = name.replace('(', '').replace(')', '').replace('/', '_').replace(' ', '_').replace(',', 'comma').replace('{','').replace('}', '').replace('[', '').replace(']', '')
    return name


cur_addr = 0
for i in range(pclntable_size):

    # 获取函数信息表
    cur_addr = pclntable_addr + (i * 8)

    # 获取函数入口偏移
    func_entry = get_wide_dword(cur_addr)  # 表示以代码段为起始地址的偏移
    func_offset = get_wide_dword(cur_addr + 4)  # 表示以pclntable为起始地址的偏移

    funcInfo_addr = pclntable_addr + func_offset

    func_entry_addr = get_wide_dword(funcInfo_addr)
    func_name_offset = get_wide_dword(funcInfo_addr + 4)
    func_name_addr = funcnametab_addr + func_name_offset
    func_name = read_string(func_name_addr)

    # 真实函数地址
    truefuncname = convert_ida_supported_string(func_name)
    truefuncentry = ida_nalt.get_imagebase() + 0x1000 + func_entry

    print(hex(truefuncentry), hex(func_offset), hex(funcInfo_addr),hex(func_entry_addr), hex(func_name_offset),
          hex(func_name_addr) ,func_name)
    # 改名
    set_name(truefuncentry, truefuncname)




#print(hex(cur_addr))