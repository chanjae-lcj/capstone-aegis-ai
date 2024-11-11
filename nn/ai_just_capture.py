import pyshark
import csv
from datetime import datetime

# CSV 파일 초기화 및 헤더 작성
with open('packet_data.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Packet Count', 'Bandwidth'])

# 패킷 캡처 설정
capture = pyshark.LiveCapture(interface='eth0')

# 패킷 데이터 추출 및 저장
for packet in capture.sniff_continuously(packet_count=50):  # 50개 패킷 캡처하고 중단
    try:
        timestamp = datetime.now()
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        packet_size = int(packet.length)
        
        # CSV 파일에 데이터 추가
        with open('packet_data.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, src_ip, dst_ip, 1, packet_size])  # 각 패킷마다 패킷 수는 1, 대역폭은 패킷 크기

    except AttributeError:
        # IP 패킷이 아닌 경우 예외 처리
        continue
