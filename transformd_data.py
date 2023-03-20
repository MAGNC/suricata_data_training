import os
import pandas as pd
from scapy.all import *
from sklearn.preprocessing import StandardScaler
from scapy.layers.inet import *
import paramiko

# SFTP连接信息
hostname = '193.200.130.243'
port = 22
username = 'root'
password = 'zxm020307'
remote_path_1 = '/var/log/suricata/eve.json'
local_path_1 = 'eve.json'  # 本地文件路径
remote_path_2 = '/var/log/suricata/'
local_path_2 = 'log.pcap'
# 删除之前下载的文件（如果存在）
if os.path.exists(local_path_1):
    os.remove(local_path_1)
if os.path.exists('network_traffic.csv'):
    os.remove('network_traffic.csv')
if os.path.exists('transformed_network_traffic.csv'):
    os.remove('transformed_network_traffic.csv')
if os.path.exists('log.pcap'):
    os.remove('log.pcap')
# 连接到SFTP服务器并下载数据文件到本地
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname=hostname, port=port, username=username, password=password)
with ssh.open_sftp() as sftp:
    sftp.get('/var/log/suricata/eve.json', 'eve.json')
    file_list = sftp.listdir(remote_path_2)
    import re

    # Compile regular expression pattern
    pattern = re.compile(r'^log\.pcap.*')
    # Get matching file names
    matching_files = [filename for filename in file_list if pattern.match(filename)]

    # Download matching files
    for filename in matching_files:
        sftp.get(os.path.join('/var/log/suricata/', filename), os.path.join('./', 'log.pcap'))

# 读取本地数据文件
df = pd.read_json('eve.json', lines=True)
df.to_csv('network_traffic.csv', index=False)
df['original_file'] = 'log.pcap'  # 本地文件路径

# 关闭SSH连接
ssh.close()

# Load the dataset

# # Convert network packets to sequences of tokens
# from tqdm import tqdm
#
#
# def extract_packets(row):
#     packets = rdpcap(row['original_file'])
#     tokens = []
#     for packet in tqdm(packets, desc=f"Processing {row['original_file']}"):
#         try:
#             features = [packet.time, packet[TCP].sport, packet[TCP].dport, packet[IP].src, packet[IP].dst]
#         except IndexError:
#             continue
#         tokens.append(features)
#     return tokens
#
#
# # 使用apply函数调用extract_packets函数，并使用tqdm显示进度
# df['tokens'] = df.apply(lambda row: extract_packets(row), axis=1)
#
# # Standardize tokens
# tokens = df['tokens'].tolist()
# flat_tokens = [item for sublist in tokens for item in sublist]
# scaler = StandardScaler()
# scaler.fit(flat_tokens)
# for i in range(len(tokens)):
#     tokens[i] = scaler.transform(tokens[i])
# df['tokens'] = tokens
#
# # Save the transformed dataset
# df.to_csv('transformed_network_traffic.csv', index=False)
