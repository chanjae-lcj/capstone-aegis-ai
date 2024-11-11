import pyshark
import numpy as np
import time
import threading
import torch
import torch.nn as nn
import yaml

# YAML 설정 파일 로드
def load_config(yaml_path):
    with open(yaml_path, 'r', encoding='utf-8') as file:
        config = yaml.safe_load(file)
    return config

# 설정 로드
config = load_config('/home/hallym/aegisai/nn/checkpoint_model_1.yaml')

# 캡처할 인터페이스 이름
INTERFACE = '\\Device\\NPF_{eth0}'

# 1x25 크기의 리스트 (저장용 리스트1)
save_list1 = np.zeros(config['model']['n_steps'])
# 60x25 크기의 리스트 (저장용 리스트2)
save_list2 = np.zeros((60, config['model']['n_steps']))
# 60x1 크기의 리스트 (예측 저장용 리스트3)
save_list3 = np.zeros((60, 1))

# 추가 변수 및 메소드
chanjae = 100  # 임계값
def jungyun():
    print("Threshold exceeded: Calling jungyun method.")

# 모델 정의 (TimeSeriesTransformer 구조 사용)
class TimeSeriesTransformer(nn.Module):
    def __init__(self, input_size, d_model, nhead, num_layers, output_size, n_steps):
        super(TimeSeriesTransformer, self).__init__()
        self.input_size = input_size
        self.d_model = d_model
        self.n_steps = n_steps

        # 입력 데이터를 임베딩 차원으로 변환하는 레이어
        self.embedding = nn.Linear(input_size, d_model)
        encoder_layer = nn.TransformerEncoderLayer(d_model=d_model, nhead=nhead, batch_first=True)
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        # 마지막 예측 값을 위한 Fully Connected Layer
        self.fc = nn.Sequential(
            nn.Dropout(0.3),
            nn.Linear(d_model, output_size)
        )

    def forward(self, x):
        x = self.embedding(x)  # (batch_size, n_steps, d_model)
        x = self.transformer_encoder(x)  # (batch_size, n_steps, d_model)
        x = x[:, -1, :]  # 마지막 타임스텝만 가져오기
        x = self.fc(x)  # (batch_size, output_size)
        return x

# 모델 인스턴스 생성 및 체크포인트 로드
input_size = config['model']['input_size']
d_model = config['model']['d_model']
nhead = config['model']['nhead']
num_layers = config['model']['num_layers']
output_size = config['model']['output_size']
n_steps = config['model']['n_steps']

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = TimeSeriesTransformer(input_size, d_model, nhead, num_layers, output_size, n_steps).to(device)

# 체크포인트 파일 로드
checkpoint_path = config['training']['checkpoint_path']
checkpoint = torch.load(checkpoint_path)
model.load_state_dict(checkpoint['model_state_dict'])
model.eval()

# 실시간으로 패킷 캡처 시작
capture = pyshark.LiveCapture(interface=INTERFACE)
capture.set_debug()

def packet_capture():
    global save_list1, save_list2, save_list3
    packet_size_sum = 0
    start_time = time.time()
    second_count = 0  # 초 단위 카운트

    print("Listening for packets...")
    for packet in capture.sniff_continuously():
        try:
            # 패킷 길이 집계
            if 'IP' in packet or 'IPV6' in packet:
                packet_size_sum += int(packet.length)
        except AttributeError:
            continue
        
        # 1초마다 리스트에 저장
        if time.time() - start_time >= 1:
            # FIFO 방식으로 저장용 리스트1 갱신
            save_list1 = np.roll(save_list1, -1)
            save_list1[-1] = packet_size_sum

            # 저장용 리스트2 갱신 (초 단위로 0에서 59까지 증가)
            row = second_count % 60
            save_list2[row, :] = save_list1.copy()  # 데이터 복사
            
            # 30초부터 예측 시작
            if second_count >= 30:
                # 예측에 사용할 입력 데이터 (이전 초의 값 사용)
                prev_row = (row - 1) % 60  # 이전 행 인덱스
                input_data = torch.tensor(save_list2[prev_row, :], dtype=torch.float32).view(1, n_steps, input_size).to(device)

                # 예측 수행
                with torch.no_grad():
                    prediction = model(input_data).item()  # 예측 값 추출

                # 예측 결과 저장
                save_list3[row, 0] = prediction

                # 실제 값과 예측 값 비교 출력
                actual_value = save_list2[row, -1]
                print(f"Second {second_count}: Prediction = {prediction}, Actual = {actual_value}")

                # 조건 만족 시 jungyun 메소드 호출
                if actual_value - prediction > chanjae:
                    jungyun()

            # 다음 초를 위한 초기화
            packet_size_sum = 0
            start_time = time.time()
            second_count += 1  # 초 카운트 증가

# 스레드 시작
thread = threading.Thread(target=packet_capture)
thread.start()

# 이 스레드에서 다른 작업을 수행할 수 있으며, 패킷 캡처는 계속 진행됩니다.
# 예제를 간단하게 유지하기 위해 메인 스레드는 바로 종료되지 않도록 설정
thread.join()
