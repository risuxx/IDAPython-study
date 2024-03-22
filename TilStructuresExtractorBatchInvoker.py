import os
import subprocess


# 串行执行cmd命令行命令
def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(result)


# 切换到ida目录下，执行命令
def run_cmd_in_ida_dir(cmd):
    ida_dir = r"D:\software\IDA7.5"
    os.chdir(ida_dir)
    print(cmd)
    run_cmd(cmd)


# 对于一个文件夹下的所有.debug文件，执行命令
def run_cmd_for_all_efi_files_in_dir(debug_dir):
    for root, dirs, files in os.walk(debug_dir):
        for file in files:
            if file.endswith(".debug"):
                print(os.path.join(root, file))
                cmd = "ida64.exe -A -c -Ltillog.txt -STilStructuresExtractorProcessor.py"
                # cmd = "ida64.exe -A -c -STilStructuresExtractorProcessor.py"
                run_cmd_in_ida_dir(cmd + " " + "\"" + os.path.join(root, file) + "\"")


if __name__ == '__main__':
    # 读取配置文件中保存的debug文件路径
    with open("StructExtractorBatchInvokerConfig.txt", "r") as f:
        now_debug_dir = f.read()
    run_cmd_for_all_efi_files_in_dir(now_debug_dir)
