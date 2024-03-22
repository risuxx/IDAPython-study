import ida_struct
import idautils
import idaapi
import json
import os


# 获取结构体中成员的数据类型
# sptr: 结构体指针，member_offset: 成员的偏移
# 结构体指针可以通过ida_struct.get_struc(sid)获取，其中sid为结构体的ID
def get_member_type(sptr, member_offset):
    tif = idaapi.tinfo_t()
    # 获取成员的指针
    mptr = ida_struct.get_member(sptr, member_offset)
    ida_struct.get_member_tinfo(tif, mptr)
    return tif.__str__()

# 遍历所有定义的结构体
def collect_structures():
    structures = []
    for struc in idautils.Structs():
        # 这里遍历Structs会得到类似于下面的内容
        # (0, 18374686479671623851, 'EFI_RETURN_STATUS_EXTENDED_DATA')
        # (1, 18374686479671623852, 'EFI_STATUS_CODE_DATA')
        # (2, 18374686479671623855, 'EFI_GUID')
        # 这里的三项为结构体的索引，结构体的ID，结构体的名称(idx, sid, name)

        # 获取结构体的名称
        struc_name = idaapi.get_struc_name(struc[1])
        # 获取结构体的大小
        struc_size = idaapi.get_struc_size(struc[1])
        # 获取结构体的成员
        members = []
        for member in idautils.StructMembers(struc[1]):     # idautils.StructMembers(sid) 返回结构体的成员
            # 这里遍历StructMembers会得到类似于下面的内容
            # (0, 'DataHeader', 20)
            # (24, 'ReturnStatus', 8)
            # (0, 'HeaderSize', 2)
            # 这里的三项为成员的偏移，成员的名称，成员的大小(offset, name, size)
            member_name = member[1]
            member_size = member[2]
            member_offset = member[0]
            sptr = ida_struct.get_struc(struc[1])
            member_type = get_member_type(sptr, member_offset)
            members.append((member_name, member_size, member_offset, member_type))
        structures.append((struc_name, struc_size, members))
    return structures


# 打印所有结构体信息
def print_structures():
    structures = collect_structures()
    for struc_name, struc_size, members in structures:
        print(f"Structure: {struc_name}, Size: {struc_size}")
        for member_name, member_size, member_offset, member_type in members:
            print(f"  Member: {member_name}, Size: {member_size}, Offset: {member_offset}, Type: {member_type}")
        print()


# 将结构体信息修改为json格式并保存在文件中
def save_structures_to_file():
    structures = collect_structures()
    structures_dict = {}
    for struc_name, struc_size, members in structures:
        members_dict = {}
        for member_name, member_size, member_offset, member_type in members:
            members_dict[member_name] = {
                "size": member_size,
                "offset": member_offset,
                "type": member_type
            }
        structures_dict[struc_name] = {
            "size": struc_size,
            "members": members_dict
        }

    structure_json_path = "structures.json"
    if not os.path.exists(structure_json_path):
        with open(structure_json_path, "w") as f:
            json.dump(structures_dict, f, indent=4)
    else:
        with open(structure_json_path, "r") as f:
            data = json.load(f)
            data.update(structures_dict)  # 对字典进行合并
        with open(structure_json_path, "w") as f:
            json.dump(data, f, indent=4)
    print("finish saving structures to file")


# 运行脚本时调用
# print_structures()
save_structures_to_file()


