import torch
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset, DataLoader
import json
from transformers import GPT2Tokenizer, GPT2LMHeadModel


def load_network_traffic_data(log_file_path):
    """
    Loads network traffic data from a Suricata JSON log file and returns a list of strings.
    Each string represents a sample of network traffic data.
    """
    with open(log_file_path, 'r') as f:
        json_str = f.read()
        log_data = json.loads(json_str)

    data = []
    for item in log_data:
        # extract relevant fields from the log item
        proto = item.get('proto', None)
        src_ip = item.get('src_ip', None)
        src_port = item.get('src_port', None)
        dest_ip = item.get('dest_ip', None)
        dest_port = item.get('dest_port', None)
        http_host = item.get('http', {}).get('hostname', '')
        http_uri = item.get('http', {}).get('url', '')
        dns_query = item.get('dns', {}).get('query', '')

        # construct a string representation of the network traffic data
        if proto == 'TCP' and http_uri:
            # HTTP request
            data.append(f"GET {http_uri} HTTP/1.1\nHost: {http_host}\n\n")
        elif proto == 'TCP' and dns_query:
            # DNS request
            data.append(f"DNS query: {dns_query}\n")
        elif proto == 'UDP':
            # UDP traffic
            data.append(f"UDP traffic between {src_ip}:{src_port} and {dest_ip}:{dest_port}\n")
        else:
            # other traffic
            data.append(f"{proto} traffic between {src_ip}:{src_port} and {dest_ip}:{dest_port}\n")

    return data


def load_labels(log_file_path):
    """
    Loads corresponding labels for network traffic data and returns a list of labels.
    Each label is either 'normal' or 'malicious'.
    """
    with open(log_file_path, 'r') as f:
        json_str = f.read()
        log_data = json.loads(json_str)
    # print("log_data:",log_data)
    labels = []
    for item in log_data:
        # determine if the network traffic is normal or malicious based on the alert field
        if item.get('alert'):
            labels.append('malicious')
        else:
            labels.append('normal')

    return labels


class JSONDataset(Dataset):
    def __init__(self, data, labels):
        self.data = data
        self.labels = labels

    def __len__(self):
        return len(self.data)

    def __getitem__(self, index):
        return self.data[index], self.labels[index]


# load dataset and labels
data = load_network_traffic_data("standard.json")  # load network traffic data
labels = load_labels("standard.json")  # load corresponding labels (normal or malicious)

# split dataset into train and test sets
train_data, test_data, train_labels, test_labels = train_test_split(data, labels, test_size=0.2, random_state=42)


print("train_data", train_data)
print("train_labels", train_labels)
# initialize tokenizer and model
tokenizer = GPT2Tokenizer.from_pretrained('gpt2')#引入分词器。
print(len(train_data), len(train_labels))
# tokenize and convert data to tensors
train_tokens = [tokenizer.encode(text) for text in train_data]
for each_train_token in train_tokens:
    while len(each_train_token) < 100:
        each_train_token.append(0)#把长度调整到100
print("train_tokens:", train_tokens)
train_tensors = [torch.tensor(token).to('cuda:0') for token in train_tokens]
print("train_tensors:", train_tensors)
print("train_tensors.shape = ", [train_tensors[i].shape for i in range(len(train_tensors))])  # 看一下每一个的长宽，不一样的还得修改。

train_labels_tokens = [tokenizer.encode(text) for text in train_labels]
print("train_labels_tokens", train_labels_tokens)
train_labels_tensor = [torch.tensor(token).to('cuda:0') for token in train_labels_tokens]
print("train_labels_tensor", train_labels_tensor)
print("train_labels_tensor.shape", [train_labels_tensor[i].shape for i in range(len(train_labels_tensor))])

json_dataset_1 = JSONDataset(train_tensors, train_labels_tensor)  # 制作数据集！
batch_size = 1
data_loader_1 = DataLoader(json_dataset_1, batch_size=batch_size, shuffle=True, drop_last=True)  # 加载数据集！


# 神经网络模型
class MyModel(torch.nn.Module):
    def __init__(self):
        super(MyModel, self).__init__()
        #print(input_size)
        self.fc1 = torch.nn.Linear(100, 10)
        self.fc2 = torch.nn.Linear(10, 1)

    def forward(self, x):
        x = self.fc1(x)
        a = torch.nn.Sigmoid()
        x = a(x)
        x = self.fc2(x)
        return x

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = MyModel()
criterion = torch.nn.MSELoss().to(device)  # 采用交叉熵
# train the model
model.to(device)
optimizer = torch.optim.SGD(model.parameters(), lr=0.001)

for epoch in range(100):  # 洗牌10次
    for batch_data, batch_labels in data_loader_1:
        batch_data = batch_data.float()
        batch_labels = batch_labels.float()
        batch_data = batch_data.to(device)
        batch_labels = batch_labels.to(device)
        # print("batch_data_shape = ", batch_data.shape)#先输出一下看看有没有特别的家伙
        # model.fc1 = torch.nn.Linear(batch_data.shape[-1], 10)
        # model.input_size = batch_data.shape[-1]  # 每个三维数组里面只有一个二维数组的时候，直接提取到二维数组的列数也就是最后一个维度！
        outputs = model(batch_data.to(device)).to(device)

        # 计算损失并进行反向传播
        loss = criterion(outputs, batch_labels.to(device))
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

    print('Epoch [{}/{}], Loss: {:.4f}'.format(epoch + 1, 100, loss.item()))

test_tokens = [tokenizer.encode(text) for text in test_data]
for each_test_token in test_tokens:
    while len(each_test_token) < 100:
        each_test_token.append(0)
test_tensors = [torch.tensor(token).to('cuda:0') for token in test_tokens]
test_labels_tokens = [tokenizer.encode(text) for text in test_labels]
test_labels_tensor = [torch.tensor(token).to('cuda:0') for token in test_labels_tokens]

json_dataset_2 = JSONDataset(train_tensors, train_labels_tensor)  # 制作数据集！
batch_size = 1
data_loader_2 = DataLoader(json_dataset_2, batch_size=batch_size, shuffle=True)  # 加载数据集！
# evaluate the model

model.eval()
with torch.no_grad():
    for batch_data, batch_labels in data_loader_2:
        # 将数据和标签传递给模型
        batch_data = batch_data.float()
        batch_labels = batch_labels.float()
        outputs = model(batch_data).to(device)
    # 打印预测结果
    print("预测结果：", outputs.item())
