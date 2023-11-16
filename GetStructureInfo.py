import idc
import idaapi
import idautils
import pickle

first_struc_idx = idaapi.get_first_struc_idx()
print(idaapi.get_struc_by_idx(first_struc_idx))
# 这里假如第一个结构体的名称是EFI_PEI_HOB_POINTERS，那么可以这样获取结构体的id，和上面那句是等价的
print(idaapi.get_struc_id("EFI_PEI_HOB_POINTERS"))

# 获取结构体的数量
struct_count = idaapi.get_struc_qty()

# 存放结构体的内容，并且使用pickle进行序列化
struct_dict = {}

for i in range(struct_count):
    struct_id = idaapi.get_struc_by_idx(i)
    struct_name = idaapi.get_struc_name(struct_id)
    print(struct_name)
    struct_dict[struct_name] = {}

    # 获取结构体的大小
    struct_size = idaapi.get_struc_size(struct_id)
    print(struct_size)

    struct_ptr = idaapi.get_struc(struct_id)
    print(struct_ptr)

    # 根据struc_t * 获取结构体中成员
    members_array = struct_ptr.members
    for member in members_array:
        # print(member)
        member_name = idaapi.get_member_name(member.id)
        print(member_name)
        print(member.soff, member.eoff)
        struct_dict[struct_name][member_name] = [member.soff, member.eoff]
        # 递归解析to do

print(struct_dict)
pickle.dump(struct_dict, open("struct_dict.pkl", "wb"))
