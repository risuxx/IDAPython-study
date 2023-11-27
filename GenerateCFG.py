import idc
import idaapi
import idautils


def cls_main(p=True):
    f = idaapi.FlowChart(idaapi.get_func(idc.here()))
    for block in f:
        if p:
            print(f"{block.start_ea:x} - {block.end_ea:x}:")
        for succ_block in block.succs():
            # 获取后继节点
            if p:
                print(f"  succs -> {succ_block.start_ea:x} - {succ_block.end_ea:x} [{succ_block.id}]")
        for pred_block in block.preds():
            # 获取前驱节点
            if p:
                print(f"  preds -> {pred_block.start_ea:x} - {pred_block.end_ea:x} [{pred_block.id}]")


cls_main()
