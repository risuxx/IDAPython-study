import idc
import idaapi
import idautils
from idc import INF_MAX_EA
from idc import INF_MIN_EA

print(idc.get_inf_attr(INF_MIN_EA))
print(idc.get_inf_attr(INF_MAX_EA))
