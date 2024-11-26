import pandas as pd
import numpy as np
import datetime
import torch
import torch.nn as nn
import yaml
from collections import defaultdict

# 설정 파일 로드
def load_config(yaml_path):
    with open(yaml_path, 'r', encoding='utf-8') as file:
        return yaml.safe_load(file)

# 트래픽 데이터 단위 변환
def parse_traffic(value):
    number, unit = value.split()
    number = float(number)
    unit = unit.strip().upper()
    if unit == 'KB':
        return number * 1024
    elif unit == 'MB':
        return number * 1024**2
    elif unit == 'GB':
        return number * 1024**3
    elif unit == 'TB':
        return number * 1024**4
    elif unit == 'B':
        return number
    else:
        raise ValueError("Unknown unit of traffic")

# 타임시리즈 변환기 모델
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

# 설정과 모델 로드
config = load_config('config.yaml')
model = TimeSeriesTransformer(config['model']['input_size'], config['model']['d_model'], config['model']['nhead'],
                              config['model']['num_layers'], config['model']['output_size'])
checkpoint = torch.load('model.pth', map_location=torch.device("cpu"))
model.load_state_dict(checkpoint['model_state_dict'])
model.eval()

# 데이터 로드 및 전처리
df = pd.read_csv('/home/hallym/aegisai/nn/traffic_data.csv', parse_dates=['timestamp'])
df['traffic'] = df['traffic'].apply(parse_traffic)

# 트래픽 데이터 가져오기
def get_traffic_data(df, current_time, window=25):
    past_data = df[(df['timestamp'] >= current_time - datetime.timedelta(seconds=window)) & (df['timestamp'] < current_time)]
    traffic_sums = past_data.groupby('timestamp')['traffic'].sum()
    return traffic_sums.reindex(pd.date_range(current_time - datetime.timedelta(seconds=window), periods=window, freq='S'), fill_value=0).values

# 트래픽 예측
def predict_traffic(model, traffic_data):
    input_tensor = torch.tensor(traffic_data, dtype=torch.float32).view(1, -1, 1)
    with torch.no_grad():
        prediction = model(input_tensor).item()
    return prediction

# 최대 트래픽 IP 찾기
def find_highest_traffic_ip(df, current_time):
    data_at_time = df[df['timestamp'] == current_time]
    if not data_at_time.empty:
        max_traffic_ip = data_at_time.groupby('src_ip')['traffic'].sum().idxmax()
    else:
        max_traffic_ip = "No traffic data available"
    return max_traffic_ip

# 현재 시간 설정 및 실제와 예측 트래픽 계산
current_time = pd.Timestamp(datetime.datetime.now())
actual_traffic = get_traffic_data(df, current_time - datetime.timedelta(seconds=2), window=1).sum()
predicted_traffic = predict_traffic(model, get_traffic_data(df, current_time - datetime.timedelta(seconds=27), window=25))

# 결과 출력 및 경고 발생
print(f"Actual traffic at {current_time - datetime.timedelta(seconds=2)}: {actual_traffic} bytes")
print(f"Predicted traffic for {current_time}: {predicted_traffic} bytes")
limit = 200  # 예시 임계값
if abs(predicted_traffic - actual_traffic) > limit:
    print("Warning: A current bandwidth attack has been detected.")
    highest_traffic_ip = find_highest_traffic_ip(df, current_time - datetime.timedelta(seconds=2))
    print(f"The IP with the highest traffic is: {highest_traffic_ip}")
    # 차단 로직은 실제 환경에 맞게 구현 필요
