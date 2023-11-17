import idc
import idaapi
import idautils

addr = idc.here()

print(hex(addr), idc.GetDisasm(addr))

for xref in idautils.XrefsTo(addr, 1):
    print(xref.type, idautils.XrefTypeName(xref.type), hex(xref.frm), hex(xref.to), xref.iscode)
    # idautils.XrefsTo(ea, flags=0)  ida_xref.XREF_ALL=0 (default), ida_xref.XREF_FAR=1, ida_xref.XREF_DATA=2
    # xref.type表明交叉引用的类型，idautils.XrefTypeName(xref.t ype)用来打印表示该类型的含义，这其中有十二种不同的类型
    # xref.frm表示引用该地址的地址，xref.to表示被引用的地址，xref.iscode()表示该地址是否在代码段中
