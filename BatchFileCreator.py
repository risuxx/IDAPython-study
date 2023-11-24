import os
import subprocess
import glob

# 对当前目录下的样本批量生成asm文件和idb文件
paths = glob.glob("*")  # 获取当前文件夹下的所有文件
ida_path = os.path.join(os.environ["ProgramFiles"], "IDA", "idaw.exe")  # 获取ida的路径，这里的environ是获取系统环境变量的值
for file_path in paths:
    if file_path.endswith(".py"):
        continue
    subprocess.call([ida_path, "-B", file_path])
