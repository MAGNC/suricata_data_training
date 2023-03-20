import json

# 读取含有多个JSON对象的原始文件
with open('eve.json', 'r') as f:
    data = f.read()

# 处理JSON字符串，将每个对象间添加逗号
data = data.replace('}\n{', '},{')

# 包装JSON数组
data = '[' + data + ']'

# 将数组写入新的JSON文件
with open('standard.json', 'w') as f:
    json.dump(json.loads(data), f)
