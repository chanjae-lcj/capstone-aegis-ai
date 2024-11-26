import subprocess
import re
import time
import torch
import torch.nn as nn
import pandas as pd
import datetime
import yaml
from collections import deque



# Transformer 기반 모델 정의
class TimeSeriesTransformer(nn.Module):
    def __init__(self, input_size, d_model, nhead, num_layers, output_size):
        super().__init__()
        self.embedding = nn.Linear(input_size, d_model)
        self.transformer_encoder = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(d_model=d_model, nhead=nhead, batch_first=True),
            num_layers
        )
        self.fc = nn.Sequential(nn.Dropout(0.3), nn.Linear(d_model, output_size))

    def forward(self, x):
        x = self.embedding(x)
        x = self.transformer_encoder(x)
        x = x[:, -1, :]
        x = self.fc(x)
        return x

# 모델 로드
def load_model(config_path, checkpoint_path):
    with open(config_path, 'r', encoding='utf-8') as file:
        config = yaml.safe_load(file)

    model = TimeSeriesTransformer(
        config['model']['input_size'], config['model']['d_model'], 
        config['model']['nhead'], config['model']['num_layers'], 
        config['model']['output_size']
    )
    checkpoint = torch.load(checkpoint_path, map_location=torch.device("cpu"))
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    return model

# 트래픽 단위 변환 (bps 처리)
def convert_traffic_to_bps(traffic_str):
    """
    트래픽 문자열(e.g., '8.57Mb', '1024B')을 float 값(bits per second)로 변환.
    """
    try:
        if traffic_str.endswith('Kb'):
            return float(traffic_str[:-2]) / 1000  # Kb → Mbps
        elif traffic_str.endswith('Mb'):
            return float(traffic_str[:-2])  # 이미 Mbps
        elif traffic_str.endswith('Gb'):
            return float(traffic_str[:-2]) * 1000  # Gb → Mbps
        elif traffic_str.endswith('b'):
            return float(traffic_str[:-1]) / (1_000_000)  # b → Mbps
        elif traffic_str.endswith('KB'):
            return float(traffic_str[:-2]) * 8 / 1000  # KB → Mbps
        elif traffic_str.endswith('B'):
            return float(traffic_str[:-1]) * 8 / (1_000_000)  # Bytes → Mbps
        else:
            return float(traffic_str)  # 이미 숫자인 경우
    except ValueError:
        return 0.0  # 변환 실패 시 0으로 반환


# def convert_traffic_to_mbps(traffic_str):
#     """
#     트래픽 문자열(e.g., '8.57Mb', '1024B')을 float 값(Mbps)로 변환.
#     """
#     try:
#         if traffic_str.endswith('Kb'):
#             return float(traffic_str[:-2]) / 1000  # Kb → Mbps
#         elif traffic_str.endswith('Mb'):
#             return float(traffic_str[:-2])  # 이미 Mbps
#         elif traffic_str.endswith('Gb'):
#             return float(traffic_str[:-2]) * 1000  # Gb → Mbps
#         elif traffic_str.endswith('b'):
#             return float(traffic_str[:-1]) / (1_000_000)  # b → Mbps
#         elif traffic_str.endswith('KB'):
#             return float(traffic_str[:-2]) * 8 / 1000  # KB → Mbps
#         elif traffic_str.endswith('B'):
#             return float(traffic_str[:-1]) * 8 / (1_000_000)  # Bytes → Mbps
#         else:
#             return float(traffic_str)  # 이미 숫자인 경우
#     except ValueError:
#         return 0.0  # 변환 실패 시 0으로 반환




# iftop 데이터 캡처
def capture_iftop_output(seconds=2):
    command = ['sudo', 'iftop', '-t', '-s', str(seconds), '-n', '-N']
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

# iftop 출력 파싱
def parse_iftop_output(output):
    """
    iftop 출력에서 IP와 트래픽 정보를 파싱하여 bps로 변환.
    """
    traffic_data = []
    lines = output.split('\n')
    for line in lines:
        if '<=' in line:
            try:
                timestamp = datetime.datetime.now()
                parts = line.split()
                src_ip = parts[0]
                traffic_str = parts[-4]
                traffic_bps = convert_traffic_to_bps(traffic_str)
                traffic_data.append((src_ip, timestamp, traffic_bps))
            except (IndexError, ValueError):
                continue
    return traffic_data

# 예측 수행
def predict_traffic(model, traffic_data):
    """
    트래픽 데이터를 Transformer 모델에 입력하여 예측.
    """
    input_tensor = torch.tensor(traffic_data, dtype=torch.float32).view(1, -1, 1)
    with torch.no_grad():
        return model(input_tensor).item()

# 가장 높은 트래픽 IP 찾기
def find_highest_traffic_ip(traffic_data):
    """
    트래픽 데이터에서 가장 높은 트래픽을 보낸 IP를 반환.
    """
    if traffic_data:
        return max(traffic_data, key=lambda x: x[2])[0]  # 트래픽이 가장 높은 IP 반환
    return None

# IP 차단

def block_ip(ip_address):
    """
    iptables 명령어를 사용하여 IP 차단. 이미 차단된 경우 중복 방지.
    """
    try:
        # 이미 차단된 IP인지 확인
        check_command = f"sudo iptables -C AI -s {ip_address} -j DROP"
        result = subprocess.run(check_command, shell=True, stderr=subprocess.PIPE)

        if result.returncode == 0:
            # 이미 차단된 상태
            print(f"IP {ip_address} is already blocked.")
        else:
            # IP 차단 명령 실행
            command = f"sudo iptables -A AI -s {ip_address} -j DROP"
            subprocess.run(command, shell=True, check=True)
            print(f"Blocked IP: {ip_address}")

    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP: {ip_address} - {e}")



# def block_ip(ip_address):
#     """
#     iptables 명령어를 사용하여 IP 차단.
#     """
#     command = f"sudo iptables -A AI -s {ip_address} -j DROP"
#     try:
#         subprocess.run(command, shell=True, check=True)
#         print(f"Blocked IP: {ip_address}")
#     except subprocess.CalledProcessError as e:
#         print(f"Error blocking IP: {e}")
    
    
#     # print(f"ddddddddddddddddddddddddddddBlocked IP: {ip_address}")
# 실시간 모니터링 및 예측
def monitor_traffic_and_predict(model, limit=200, window=25):
    """
    실시간으로 트래픽을 분석하고 예측값과 비교하며 이상 트래픽을 감지 및 차단.
    """
    traffic_history = deque(maxlen=window)  # 최근 25초의 트래픽 저장

    while True:
        output = capture_iftop_output(seconds=2)
        current_traffic = parse_iftop_output(output)

        # 트래픽 기록 업데이트
        total_traffic_bps = sum(data[2] for data in current_traffic)
        traffic_history.append(total_traffic_bps)

        # 예측 수행
        if len(traffic_history) == window:
            predicted_traffic = 2*(predict_traffic(model, list(traffic_history)))
            print(f"Actual traffic: {total_traffic_bps} Mbps")
            print(f"Predicted traffic: {predicted_traffic} Mbps")

            # 임계값 초과 확인
            if predicted_traffic != 0:
                if total_traffic_bps/predicted_traffic*100 > limit:
                    print("Warning: Anomalous traffic detected.")
                    highest_traffic_ip = find_highest_traffic_ip(current_traffic)
                    if highest_traffic_ip:
                        block_ip(highest_traffic_ip)

        time.sleep(1)  # 1초 대기

# 실행
if __name__ == "__main__":
    config_path = '/home/hallym/aegisai/nn/checkpoint_model_1.yaml'
    checkpoint_path = '/home/hallym/aegisai/nn/checkpoint_model_1.pth.tar'
    model = load_model(config_path, checkpoint_path)
    monitor_traffic_and_predict(model)
