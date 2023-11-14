import idc
import idaapi
import idautils

for seg in idautils.Segments():
    print(idc.get_segm_name(seg), hex(idc.get_segm_start(seg)), hex(idc.get_segm_end(seg)))
