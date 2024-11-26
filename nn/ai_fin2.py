import pandas as pd
import numpy as np
import datetime
import torch
import torch.nn as nn
import yaml
from collections import defaultdict

def load_config(yaml_path):
    with open(yaml_path, 'r', encoding='utf-8') as file:
        return yaml.safe_load(file)

config = load_config('/home/hallym/aegisai/nn/checkpoint_model_1.yaml')

class TimeSeriesTransformer(nn.Module):
    def __init__(self, input_size, d_model, nhead, num_layers, output_size):
        super().__init__()
        self.embedding = nn.Linear(input_size, d_model)
        self.transformer_encoder = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(d_model=d_model, nhead=nhead, batch_first=True),
            num_layers)
        self.fc = nn.Sequential(nn.Dropout(0.3), nn.Linear(d_model, output_size))

    def forward(self, x):
        x = self.embedding(x)
        x = self.transformer_encoder(x)
        x = x[:, -1, :]
        x = self.fc(x)
        return x

model = TimeSeriesTransformer(config['model']['input_size'], config['model']['d_model'], config['model']['nhead'],
                              config['model']['num_layers'], config['model']['output_size'])
checkpoint = torch.load('/home/hallym/aegisai/nn/checkpoint_model_1.pth.tar', map_location=torch.device("cpu"))
model.load_state_dict(checkpoint['model_state_dict'])
model.eval()

df = pd.read_csv('/home/hallym/aegisai/nn/traffic_data.csv', parse_dates=['timestamp'])

def get_traffic_data(df, current_time, window=25):
    past_data = df[(df['timestamp'] >= current_time - datetime.timedelta(seconds=window)) & (df['timestamp'] < current_time)]
    traffic_sums = past_data.groupby('timestamp')['traffic'].sum()
    return traffic_sums.reindex(pd.date_range(current_time - datetime.timedelta(seconds=window), periods=window, freq='S'), fill_value=0).values

def predict_traffic(model, traffic_data):
    input_tensor = torch.tensor(traffic_data, dtype=torch.float32).view(1, -1, 1)
    with torch.no_grad():
        prediction = model(input_tensor).item()
    return prediction

def find_highest_traffic_ip(df, current_time):
    data_at_time = df[df['timestamp'] == current_time]
    if not data_at_time.empty:
        max_traffic_ip = data_at_time.groupby('src_ip')['traffic'].sum().idxmax()
    else:
        max_traffic_ip = "No traffic data available"
    return max_traffic_ip

current_time = pd.Timestamp(datetime.datetime.now())
actual_traffic = get_traffic_data(df, current_time - datetime.timedelta(seconds=2), window=1).sum()
predicted_traffic = predict_traffic(model, get_traffic_data(df, current_time - datetime.timedelta(seconds=27), window=25))

print(f"Actual traffic at {current_time - datetime.timedelta(seconds=2)}: {actual_traffic} MB")
print(f"Predicted traffic for {current_time}: {predicted_traffic} MB")

limit = 200  # 예시 임계값
if abs(predicted_traffic - actual_traffic) > limit:
    print("Warning: A current bandwidth attack has been detected.")
    highest_traffic_ip = find_highest_traffic_ip(df, current_time - datetime.timedelta(seconds=2))
    print(f"The IP with the highest traffic is: {highest_traffic_ip}")
    # 차단 로직은 실제 환경에 맞게 구현 필요
