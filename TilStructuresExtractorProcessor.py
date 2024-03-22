import ida_auto
import ida_nalt
import ida_pro
import ida_struct
import idautils
import idc
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
            print(f"file path is {ida_nalt.get_root_filename()}")
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


def print_structures(structures):
    for struc_name, struc_size, members in structures:
        print(f"Structure: {struc_name}, Size: {struc_size}")
        for member_name, member_size, member_offset, member_type in members:
            print(f"  Member: {member_name}, Size: {member_size}, Offset: {member_offset}, Type: {member_type}")
        print("end of structure\n")


def save_structures_to_file(structures):
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
    print("start to save structures to file")
    structure_json_path = r"D:\ris\projects\Graduation Project\experiment\edk2_build_debug_files\structures.json"
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


def main():
    ida_auto.auto_wait()
    structures = collect_local_type_structures()
    print_structures(structures)
    save_structures_to_file(structures)
    ida_pro.qexit(0)


if __name__ == '__main__':
    main()
