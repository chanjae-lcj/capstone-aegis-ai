import pyshark
import csv
import time
# 캡처할 인터페이스 지정
interface = 'any'

# 캡처 객체 생성
capture = pyshark.LiveCapture(interface=interface)

# CSV 파일 설정
csv_file = open('packet_capture2.csv', 'w', newline='')
csv_writer = csv.writer(csv_file)
csv_writer.writerow(['Time', 'Source IP', 'Destination IP', 'Packets', 'Bandwidth (Bytes)'])

# 변수 초기화
last_src_ip = None
packet_count = 0
packet_size_sum = 0

print("Listening for packets...")
for packet in capture.sniff_continuously():
    try:
        # 현재 패킷의 소스 IP
        current_src_ip = packet.ip.src
        destination_ip = packet.ip.dst
        # 동일한 소스 IP에서 패킷을 누적
        if current_src_ip == last_src_ip or last_src_ip is None:
            packet_count += 1
            packet_size_sum += int(packet.length)
        else:
            # 현재 시간
            current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        
            # 이전 IP의 데이터를 CSV 파일 및 콘솔에 출력
            csv_writer.writerow([current_time, last_src_ip, destination_ip, packet_count, packet_size_sum])
            print(f"Time: {current_time}, Src IP: {last_src_ip},Dst IP: {destination_ip}, Packets: {packet_count}, Bandwidth: {packet_size_sum} Bytes")
            
            # 새 IP에 대한 데이터 누적 시작
            packet_count = 1
            packet_size_sum = int(packet.length)
        
        # 마지막 소스 IP 업데이트
        last_src_ip = current_src_ip

    except AttributeError:
        # IP 패킷이 아닌 경우 건너뛰기
        continue

# 마지막 패킷 데이터 출력
if packet_count > 0:
    current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    csv_writer.writerow([current_time, last_src_ip, detination_ip, packet_count, packet_size_sum])
    print(f"Time: {current_time}, Src IP: {last_src_ip}, DstIP: {destination_ip}, Packets: {packet_count}, Bandwidth: {packet_size_sum} Bytes")

# 파일 닫기
csv_file.close()
