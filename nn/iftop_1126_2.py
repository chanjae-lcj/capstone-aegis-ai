import subprocess
import re
import csv
import time
from datetime import datetime


# def clear_csv_content(filename="traffic_data.csv"):
#     with open(filename, 'w', newline='') as file:
#         pass

def clear_csv_content(filename="traffic_data.csv"):
    """CSV 파일의 내용을 비우고 첫 행에 헤더를 추가합니다."""
    with open(filename, 'w', newline='') as file:
        fieldnames = ['num', 'src_ip', 'timestamp', 'xxx', 'traffic']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()  # 헤더 작성



clear_csv_content("traffic_data.csv")

def convert_traffic_to_float(traffic_str):
    """
    트래픽 문자열(e.g., '8.57Mb')을 float 값(MB)로 변환.
    """
    try:
        if traffic_str.endswith('Kb'):
            return float(traffic_str[:-2]) / 1000  # Kb → MB
        elif traffic_str.endswith('Mb'):
            return float(traffic_str[:-2])  # Mb
        elif traffic_str.endswith('Gb'):
            return float(traffic_str[:-2]) * 1000  # Gb → MB
        elif traffic_str.endswith('b'):
            return float(traffic_str[:-1]) / (1024 * 1024)  # Bytes → MB
        elif traffic_str.endswith('KB'):
            return float(traffic_str[:-2]) / 1024  # KB → MB
        else:
            return float(traffic_str)  # 이미 숫자인 경우
    except ValueError:
        print(f"Error converting traffic value: {traffic_str}")
        return 0.0  # 변환 실패 시 0으로 반환






def run_iftop(seconds=2):
    """iftop을 실행하여 네트워크 트래픽 데이터를 캡처합니다."""
    command = ['sudo', 'iftop', '-t', '-s', str(seconds), '-n', '-N']
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

def parse_iftop_output(output):
    """iftop 출력에서 IP와 트래픽 정보를 파싱합니다."""
    traffic_data = []
    lines = output.split('\n')
    for line in lines:
        # '=>' 방향의 트래픽 데이터만 처리
        if '<=' in line:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            parts = line.split()
            num = parts[0]
            source_ip = parts[1]
            traffic_str = parts[-4] # 보통 트래픽 정보는 라인의 끝에서 두 번째에 위치
            traffic = convert_traffic_to_float(traffic_str)

            traffic_data.append((num, traffic))
    return traffic_data

def save_to_csv(data, timecount, filename="traffic_data.csv"):
    """파싱된 데이터와 timecount 값을 CSV 파일에 저장합니다."""
    with open(filename, 'a', newline='') as file:
        writer = csv.writer(file)
        # 각 행에 timecount 추가
        for row in data:
            writer.writerow([timecount] + list(row))
            print("writing")
def monitor_traffic():
    timecount = 0
    while True:
        output = run_iftop()
        traffic_data = parse_iftop_output(output)
        save_to_csv(traffic_data, timecount)
        timecount += 1  # timecount 증가
        time.sleep(1)  # 1초 대기

# 스크립트 시작
monitor_traffic()