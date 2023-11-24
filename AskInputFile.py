import ida_kernwin
import idc
import idaapi
import idautils

# 弹出窗口询问用户输入文件名，会直接弹出一个文件对话框就是文件管理器那种，让你去选择文件
# 假如第一个forsave参数置为1，那么会弹出保存文件的对话框
filename = ida_kernwin.ask_file(0, "*.*", "Please select a file to open")
