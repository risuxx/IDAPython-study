import re
import json
log_file = "tillog.txt"
# 用于收集匹配结果的列表
matches = {}
try:
    with open(log_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        # 将文件内容组合成一个长字符串，以便跨行匹配
        log_content = "".join(lines)
        # 使用正则来匹配
        all_matches = re.findall(r"could not convert typeinfo\nFailed to import structure (.*?)\nfile path is (.*?)\.debug", log_content, re.DOTALL)
        for match in all_matches:
            struct_name, file_name = match
            if file_name not in matches:
                matches[file_name] = []
            matches[file_name].append(struct_name)
            print(f"Found structure: {struct_name}, file path: {file_name}.debug")

except FileNotFoundError:
    print(f"Error: File {log_file} not found.")
except Exception as e:
    print(f"An error occurred: {e}")

print(matches)

save_path = "til_structures.json"
with open(save_path, "w") as f:
    json.dump(matches, f, indent=4)
