import ida_struct
import idautils
import idc
import idaapi
import json
from StructExtractor import get_member_type
import os


def collect_local_type_structures():
    local_types_cnt = idc.get_ordinal_qty()
    print(local_types_cnt)
    structures = []
    for i in range(0, local_types_cnt):
        print(f"idx: {i}, local_type_name: {idc.get_numbered_type_name(i)}")
        # 这里我想通过将结构体的名称导入到idb的方式来获取结构体的大小和成员
        # 但是ida在加入过多结构体后会出现问题，因此考虑每次只导入一个结构体
        # 再提取出结构体的信息后将其删除
        local_type = idc.get_numbered_type_name(i)
        print(f"type of local_type: {type(local_type)}")
        # 这里的local_type可能为None
        # idx: 0, local_type_name: None
        # type of local_type: <class 'NoneType'>
        if local_type is None:
            continue
        sid = idc.import_type(-1, local_type)
        if sid == 0xffffffffffffffff:
            print(f"Failed to import structure {local_type}")
            continue
        # 获取结构体的名称
        struc_name = idaapi.get_struc_name(sid)
        # 获取结构体的大小
        struc_size = idaapi.get_struc_size(sid)
        # 获取结构体的成员
        members = []
        print(f"sid: {sid}, structure: {local_type}")
        sptr = ida_struct.get_struc(sid)
        try:
            for member in idautils.StructMembers(sid):  # idautils.StructMembers(sid) 返回结构体的成员
                # 这里遍历StructMembers会得到类似于下面的内容
                # (0, 'DataHeader', 20)
                # (24, 'ReturnStatus', 8)
                # (0, 'HeaderSize', 2)
                # 这里的三项为成员的偏移，成员的名称，成员的大小(offset, name, size)
                member_name = member[1]
                member_size = member[2]
                member_offset = member[0]
                member_type = get_member_type(sptr, member_offset)
                members.append((member_name, member_size, member_offset, member_type))
            # 删除结构体
            ida_struct.del_struc(sptr)
            print(f"Deleted structure {local_type}")
            structures.append((struc_name, struc_size, members))
        except Exception as e:
            print(f"Failed to get members for {local_type}")
            continue
    return structures


def print_structures():
    structures = collect_local_type_structures()
    for struc_name, struc_size, members in structures:
        print(f"Structure: {struc_name}, Size: {struc_size}")
        for member_name, member_size, member_offset, member_type in members:
            print(f"  Member: {member_name}, Size: {member_size}, Offset: {member_offset}, Type: {member_type}")
        print("end of structure\n")


def save_structures_to_file():
    structures = collect_local_type_structures()
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

    # 假如没有structures.json文件就创建一个
    # 创建structures.json
    if not os.path.exists("structures.json"):
        with open("structures.json", "w") as f:
            json.dump(structures_dict, f, indent=4)
    else:
        with open("structures.json", "r") as f:
            data = json.load(f)
            data.update(structures_dict)  # 对字典进行合并
        with open("structures.json", "w") as f:
            json.dump(data, f, indent=4)


save_structures_to_file()
