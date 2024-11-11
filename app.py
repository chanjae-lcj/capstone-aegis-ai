from flask import Flask, render_template, request, redirect, url_for, jsonify, session, send_from_directory
# from sqlalchemy import create_engine
import pam
import re
import os
import json
import psutil   # cpu 관련 라이브러리
from firewall import is_valid_ip, is_valid_port, run_iptables_command, list_drop_rules, list_accept_rules
from bgp import delete_bgp_protocol, add_bgp_protocol, enable_bgp_protocol,list_bgp_protocols,disable_bgp_protocol  # bgp.py 모듈을 import
from static_routes import add_static_route, delete_static_route, list_routes  # static_routes 모듈을 import
from nat import list_post_rules, list_pre_rules, run_nat_command
from user import run_user_command, list_user, add_user, delete_user, pass_user, list2_user
from ai import list_ai_ip_rules
from inf import list_inf
from collections import deque
from threading import Thread, Lock
from flask_socketio import SocketIO, emit
import threading
import time
import subprocess
from collections import deque
import signal # ai에 사용

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # 세션을 위한 비밀키 설정
socketio = SocketIO(app)

# PAM 객체 생성
pam_auth = pam.pam()




# ---------------------컨트롤러--------------------- 컨트롤러 시작

# 루트 접속시
@app.route('/')
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template("login.html")


# 로그인 파트
@app.route('/login_check', methods=['POST'])
def login_check():
    username = request.form['username']
    password = request.form['password']

    if pam_auth.authenticate(username, password):
        session['username'] = username
        return jsonify(success=True)
    else:
        return jsonify(success=False, message="Failed. Please try again.")


# 로그아웃 파트
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


# 메인 페이지, 대시보드
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("dashboard.html", username=username)


# IP 차단 
@app.route('/rule')
def rule():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("rule.html", username=username)


# IP 허용 
@app.route('/allow')
def allow():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("allow.html", username=username)


# AI 자동 차단 규칙 
@app.route('/ai')
def ai():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("ai.html", username=username)


# AI 모델 설정 
@app.route('/model')
def model():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("model.html", username=username)


# NAT 포트 포워딩
@app.route('/port')
def port():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("port.html", username=username)


# NAT sNat / dNat
@app.route('/nat')
def nat():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("nat.html", username=username)

# VPN
@app.route('/openvpn')
def openvpn():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("openvpn.html", username=username)

# PPTP
@app.route('/pptp')
def pptp():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("pptp.html", username=username)

# l2tp
@app.route('/l2tp')
def l2tp():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("l2tp.html", username=username)

# 인터페이스
@app.route('/interface')
def interface():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("interface.html", username=username)

# 사용자 계정 정보
@app.route('/user')
def user():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("user.html", username=username)

# 문서화
@app.route('/document')
def document():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("document.html", username=username)


# ---------------------컨트롤러--------------------- 컨트롤러 끝



# ------------------- gh.w ----------------------- BGP 시작
# BGP 페이지 
@app.route('/bgp')
def bgp():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("bgp.html", username=username)

# BGP 프로토콜 삭제
@app.route('/bgp/delete/<protocol_name>', methods=['DELETE'])
def delete_bgp(protocol_name):
    if 'username' not in session:
        return redirect(url_for('login'))
    result, status_code = delete_bgp_protocol(protocol_name)
    return jsonify(result), status_code

# 새로운 BGP 프로토콜 추가
@app.route('/bgp/add', methods=['POST'])
def add_bgp():
    if 'username' not in session:
        return redirect(url_for('login'))
    data = request.json
    protocol_name = data.get("protocol_name")
    neighbor_ip = data.get("neighbor_ip")
    local_as = data.get("local_as")
    neighbor_as = data.get("neighbor_as")
    filter_option = data.get("filter")  # 필터 옵션 받기
    custom_filter = data.get("custom_filter")  # 커스텀 필터 받기

    result, status_code = add_bgp_protocol(protocol_name, neighbor_ip, local_as, neighbor_as, filter_option, custom_filter)
    return jsonify(result), status_code


# BGP 프로토콜 활성화
@app.route('/bgp/enable/<protocol_name>', methods=['POST'])
def enable_bgp(protocol_name):
    if 'username' not in session:
        return redirect(url_for('login'))
    result, status_code = enable_bgp_protocol(protocol_name)
    return jsonify(result), status_code

# BGP 프로토콜 리스트 조회
@app.route('/bgp/list', methods=['GET'])
def list_bgp():
    if 'username' not in session:
        return redirect(url_for('login'))
    result, status_code = list_bgp_protocols()
    return jsonify(result), status_code

@app.route('/bgp/disable/<protocol_name>', methods=['POST'])
def disable_bgp(protocol_name):
    if 'username' not in session:
        return redirect(url_for('login'))
    result, status_code = disable_bgp_protocol(protocol_name)
    return jsonify(result), status_code


# ------------------- gh.w -----------------------  BGP






# ------------------- gh.w ----------------------- static
# 정적 라우팅 추가
# 라우팅 테이블 조회
@app.route('/list_routes', methods=['GET'])
def list_route():
    if 'username' not in session:
        return redirect(url_for('login'))
    result, status_code = list_routes()
    return jsonify(result), status_code

# 정적 라우팅 추가
@app.route('/add_static_route', methods=['POST'])
def add_route():
    if 'username' not in session:
        return redirect(url_for('login'))
    data = request.json
    destination = data.get('destination')
    gateway = data.get('gateway')
    interface = data.get('interface')  # 선택적 인터페이스

    result, status_code = add_static_route(destination, gateway, interface)
    return jsonify(result), status_code

def netmask_to_cidr(netmask):
    return sum([bin(int(octet)).count('1') for octet in netmask.split('.')])


# 정적 라우팅 삭제
@app.route('/delete_static_route', methods=['POST'])
def delete_route():
    if 'username' not in session:
        return redirect(url_for('login'))
    data = request.json
    destination = data.get('destination')
    mask = data.get('mask')

    # 서브넷 마스크를 CIDR로 변환
    cidr = netmask_to_cidr(mask)
    full_route = f"{destination}/{cidr}"
    
    result, status_code = delete_static_route(full_route)
    return jsonify(result), status_code


# 정적 라우팅 관리 페이지
@app.route('/routes')
def routes_page():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("routes.html", username=username)

# ------------------- gh.w -----------------------  static

# ------------------- ai -------------------------  ai 패킷
"""
# 1개의 데이터를 저장하는 FIFO 큐, 최대 길이 1
ai_traffic_data = deque(maxlen=25)

# 5분 동안의 네트워크 트래픽 양을 저장할 변수 (이전 측정값)
ai_previous_traffic = {
    'bytes_sent': 0,
    'bytes_recv': 0,
    'packets_sent': 0,
    'packets_recv': 0,
    'errin': 0,
    'errout': 0,
    'dropin': 0,
    'dropout': 0
}

# 쓰레드 안전성을 위한 락(lock)
ai_lock = Lock()

def ai_add_network_traffic(new_data):
    global ai_previous_traffic

    ai_current_traffic = {
        'bytes_sent': new_data.bytes_sent - previous_traffic['bytes_sent'],
        'bytes_recv': new_data.bytes_recv - previous_traffic['bytes_recv'],
        'packets_sent': new_data.packets_sent - previous_traffic['packets_sent'],
        'packets_recv': new_data.packets_recv - previous_traffic['packets_recv'],
        'errin': new_data.errin - previous_traffic['errin'],
        'errout': new_data.errout - previous_traffic['errout'],
        'dropin': new_data.dropin - previous_traffic['dropin'],
        'dropout': new_data.dropout - previous_traffic['dropout'],
    }

    # 현재 값을 저장해서 다음 10초 간격에 대비
    ai_previous_traffic = {
        'bytes_sent': new_data.bytes_sent,
        'bytes_recv': new_data.bytes_recv,
        'packets_sent': new_data.packets_sent,
        'packets_recv': new_data.packets_recv,
        'errin': new_data.errin,
        'errout': new_data.errout,
        'dropin': new_data.dropin,
        'dropout': new_data.dropout
    }

    # 데이터를 큐에 저장 (5분마다)
    with ai_lock:
        ai_traffic_data.append(ai_current_traffic)

    # 클라이언트로 실시간 데이터 전송
    socketio.emit('ai_traffic_data', ai_current_traffic)

def ai_network_traffic_generator():
    # 이전 네트워크 트래픽 초기화
    ai_data = psutil.net_io_counters()
    ai_add_network_traffic(ai_data)

    # 실시간 네트워크 트래픽 데이터를 수집
    while True:
        ai_data = psutil.net_io_counters()  # 네트워크 I/O 데이터를 수집
        add_network_traffic(ai_data)  # 수집된 데이터를 처리
        time.sleep(1)  # 10초마다 트래픽 데이터 추가

# 네트워크 트래픽 데이터 수집을 별도 쓰레드에서 실행
def ai_start_network_traffic_thread():
    thread = Thread(target=ai_network_traffic_generator)
    thread.daemon = True
    thread.start()
# ----------------- ai ---------------------------- ai 패킷
"""
# ----------------- 네트워크 정보 -------------------  네트워크 정보 시작

# 1개의 데이터를 저장하는 FIFO 큐, 최대 길이 1
traffic_data = deque(maxlen=1)

# 5분 동안의 네트워크 트래픽 양을 저장할 변수 (이전 측정값)
previous_traffic = {
    'bytes_sent': 0,
    'bytes_recv': 0,
    'packets_sent': 0,
    'packets_recv': 0,
    'errin': 0,
    'errout': 0,
    'dropin': 0,
    'dropout': 0
}

# 쓰레드 안전성을 위한 락(lock)
lock = Lock()

def add_network_traffic(new_data):
    global previous_traffic

    current_traffic = {
        'bytes_sent': new_data.bytes_sent - previous_traffic['bytes_sent'],
        'bytes_recv': new_data.bytes_recv - previous_traffic['bytes_recv'],
        'packets_sent': new_data.packets_sent - previous_traffic['packets_sent'],
        'packets_recv': new_data.packets_recv - previous_traffic['packets_recv'],
        'errin': new_data.errin - previous_traffic['errin'],
        'errout': new_data.errout - previous_traffic['errout'],
        'dropin': new_data.dropin - previous_traffic['dropin'],
        'dropout': new_data.dropout - previous_traffic['dropout'],
    }

    # 현재 값을 저장해서 다음 10초 간격에 대비
    previous_traffic = {
        'bytes_sent': new_data.bytes_sent,
        'bytes_recv': new_data.bytes_recv,
        'packets_sent': new_data.packets_sent,
        'packets_recv': new_data.packets_recv,
        'errin': new_data.errin,
        'errout': new_data.errout,
        'dropin': new_data.dropin,
        'dropout': new_data.dropout
    }

    # 데이터를 큐에 저장 (5분마다)
    with lock:
        traffic_data.append(current_traffic)

    # 클라이언트로 실시간 데이터 전송
    socketio.emit('traffic_data2', current_traffic)

def network_traffic_generator():
    # 이전 네트워크 트래픽 초기화
    data = psutil.net_io_counters()
    add_network_traffic(data)

    # 실시간 네트워크 트래픽 데이터를 수집
    while True:
        data = psutil.net_io_counters()  # 네트워크 I/O 데이터를 수집
        add_network_traffic(data)  # 수집된 데이터를 처리
        time.sleep(1)  # 10초마다 트래픽 데이터 추가

# 네트워크 트래픽 데이터 수집을 별도 쓰레드에서 실행
def start_network_traffic_thread():
    thread = Thread(target=network_traffic_generator)
    thread.daemon = True
    thread.start()

# Emit real-time network data every second
# @socketio.on('request_network_data')
# def handle_network_data():
#     network_data = {}
#     net_io = psutil.net_io_counters(pernic=True)  # Get network stats for each interface

#     # Structure the data
#     for interface, stats in net_io.items():
#         network_data[interface] = {
#             'bits_recv': int(stats.bytes_recv * 8 * 10**(-6)),  # 들어오는 비트, 단위(Mbit)
#             'bits_sent': int(stats.bytes_sent * 8 * 10**(-6))  # 보내는 비트, 단위(Mbit)
#         }
    
#     # Emit the network data to the client
#     emit('network_data', network_data)

# ----------------- 네트워크 정보 -------------------  네트워크 정보 끝


# ---------------- 네트워크 그래프 1. -------------------- 첫 번째 네트워크 그래프 시작.
# 1개의 데이터를 저장하는 FIFO 큐, 최대 길이 11
traffic_graph = deque(maxlen=1)

# 5분 동안의 네트워크 트래픽 양을 저장할 변수 (이전 측정값)
previous_graph = {
    'bytes_sent': 0,
    'bytes_recv': 0,
}

# 쓰레드 안전성을 위한 락(lock)
lock2 = Lock()

def add_network_graph(new_data):
    global previous_graph

    current_graph = {
        'bytes_sent': new_data.bytes_sent - previous_graph['bytes_sent'],
        'bytes_recv': new_data.bytes_recv - previous_graph['bytes_recv']
    }

    previous_graph = {
        'bytes_sent': new_data.bytes_sent,
        'bytes_recv': new_data.bytes_recv
    }

    # 데이터를 큐에 저장 (5분마다)
    with lock:
        traffic_data.append(current_graph)

    # 클라이언트로 실시간 데이터 전송
    socketio.emit('traffic_graph', current_graph)

def network_traffic_generator2():
    # 이전 네트워크 트래픽 초기화
    data = psutil.net_io_counters()
    add_network_graph(data)

    # 실시간 네트워크 트래픽 데이터를 수집
    while True:
        data = psutil.net_io_counters()  # 네트워크 I/O 데이터를 수집
        add_network_graph(data)  # 수집된 데이터를 처리
        time.sleep(1)  # 300초마다 트래픽 데이터 추가

# 네트워크 트래픽 데이터 수집을 별도 쓰레드에서 실행
def start_network_traffic_thread2():
    thread = Thread(target=network_traffic_generator2)
    thread.daemon = True
    thread.start()
# ---------------- 네트워크 그래프 1. -------------------- 첫 번째 네트워크 그래프 끝.


# ---------------- 네트워크 그래프 2. -------------------- 두 번째 네트워크 그래프 시작.
# 11개의 데이터를 저장하는 FIFO 큐, 최대 길이 11
traffic_graph5 = deque(maxlen=11)

# 5분 동안의 네트워크 트래픽 양을 저장할 변수 (이전 측정값)
previous_graph5 = {
    'bytes_sent': 0,
    'bytes_recv': 0,
}

# 쓰레드 안전성을 위한 락(lock)
lock5 = Lock()

def add_network_graph5(new_data):
    global previous_graph5

    current_graph5 = {
        'bytes_sent': new_data.bytes_sent - previous_graph5['bytes_sent'],
        'bytes_recv': new_data.bytes_recv - previous_graph5['bytes_recv']
    }

    previous_graph5 = {
        'bytes_sent': new_data.bytes_sent,
        'bytes_recv': new_data.bytes_recv
    }

    # 데이터를 큐에 저장 (5분마다)
    with lock2:
        traffic_graph5.append(current_graph5)

    # 실시간 데이터 전송
    socketio.emit('traffic_graph5', current_graph5)

# 클라이언트 연결 시 기존의 11개 데이터를 전송하는 이벤트 처리
@socketio.on('connect')
def handle_connect5():
    # 클라이언트가 연결될 때 지난 11개의 데이터를 전송
    with lock5:
        socketio.emit('initial_traffic_data', list(traffic_graph5))  # 자료구조 전체 데이터를 전송

def network_traffic_generator5():
    # 이전 네트워크 트래픽 초기화
    data = psutil.net_io_counters()
    add_network_graph5(data)

    # 실시간 네트워크 트래픽 데이터를 수집
    while True:
        data = psutil.net_io_counters()  # 네트워크 I/O 데이터를 수집
        add_network_graph5(data)  # 수집된 데이터를 처리
        time.sleep(300)  # 300초마다 트래픽 데이터 추가

# 네트워크 트래픽 데이터 수집을 별도 쓰레드에서 실행
def start_network_traffic_thread5():
    thread = Thread(target=network_traffic_generator5)
    thread.daemon = True
    thread.start()

# ---------------- 네트워크 그래프 2. -------------------- 두 번째 네트워크 그래프 끝.



# -------------- 시스템 정보 ----------------

# CPU 사용량 데이터
@app.route('/cpu_usage')
def cpu_usage():
    # psutil을 사용해 CPU 사용량을 퍼센트로 반환
    cpu_percent = psutil.cpu_percent(interval=1)
    return jsonify(cpu=cpu_percent)

@app.route('/system_info')
def system_info():
    try:
        # 메모리 정보
        memory = psutil.virtual_memory()
        memory_total = memory.total / (1024 ** 3)  # GB
        memory_used = memory.used / (1024 ** 3)  # GB
        memory_percent = memory.percent

        # 디스크 정보
        disk = psutil.disk_usage('/')
        disk_total = disk.total / (1024 ** 3)  # GB
        disk_used = disk.used / (1024 ** 3)  # GB
        disk_percent = disk.percent

        return jsonify({
            'memory_total': memory_total,
            'memory_used': memory_used,
            'memory_percent': memory_percent,
            'disk_total': disk_total,
            'disk_used': disk_used,
            'disk_percent': disk_percent,
        })
    except Exception as e:
        return jsonify({'error': str(e)})

# os 라이브러리를 사용한 System 정보
@app.route('/os_info')
def os_info():
    try:
        user_name = os.getlogin() # 로그인 유저 이름
        sys_info = os.uname() # 시스템 정보
        cpu_count = os.cpu_count() # cpu 개수
        ip_address = os.popen('hostname -I').read().strip() # ip 주소
        with open('/etc/resolv.conf', 'r') as f: # dns 정보
            dns_info = [line.strip() for line in f.readlines() if line.startswith('nameserver')]
        net_info = os.popen("ip -o -4 addr show scope global").read().strip() # 네트워크 정보

        return jsonify({
            'user_name' : user_name,
            'sys_info' : sys_info,
            'cpu_count' : cpu_count,
            'ip_address' : ip_address,
            'dns_info' : dns_info,
            'net_info' : net_info
        })
    
    except Exception as e:
        return jsonify({'error': str(e)})

# ------------------------------------------------------

# -------------------- gh.w --------------------------   ip 차단 시작.


# 차단된 IP, 포트 목록 가져오기
@app.route('/iptables/list/drop', methods=['GET'])
def drop_rules():
    result = list_drop_rules()
    if result["error"]:
        return jsonify({"error": result["error"]}), 500
    
    return jsonify({"output": result["output"]})

# 허용된 IP, 포트 목록 가져오기
@app.route('/iptables/list/accept', methods=['GET'])
def accept_rules():
    result = list_accept_rules()
    if result["error"]:
        return jsonify({"error": result["error"]}), 500
    
    return jsonify({"output": result["output"]})

# IP별 차단
@app.route('/iptables/block_ip', methods=['POST'])
def block_ip():
    data = request.json
    if not data or 'ip' not in data:
        return jsonify({"error": "IP address is required"}), 400
    
    ip = data['ip']
    
    # IP 검증
    if not is_valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400

    command = f"sudo iptables -A INPUT -s {ip} -j DROP"
    result = run_iptables_command(command)

    if result["error"]:
        return jsonify({"error": result["error"]}), 500
    
    return jsonify({"output": result["output"]})

# 포트별 차단
@app.route('/iptables/block_port', methods=['POST'])
def block_port():
    data = request.json
    if not data or 'port' not in data:
        return jsonify({"error": "Port number is required"}), 400
    
    port = data['port']
    protocol = data.get('protocol', 'tcp')  # 기본 프로토콜은 TCP로 설정
    
    # 포트 검증
    if not is_valid_port(port):
        return jsonify({"error": "Invalid port number"}), 400

    command = f"sudo iptables -A INPUT -p {protocol} --dport {port} -j DROP"
    result = run_iptables_command(command)

    if result["error"]:
        return jsonify({"error": result["error"]}), 500
    
    return jsonify({"output": result["output"]})

# IP 및 포트별 차단
@app.route('/iptables/block_ip_port', methods=['POST'])
def block_ip_port():
    data = request.json
    if not data or 'ip' not in data or 'port' not in data:
        return jsonify({"error": "Both IP address and port number are required"}), 400
    
    ip = data['ip']
    port = data['port']
    protocol = data.get('protocol', 'tcp')  # 기본 프로토콜은 TCP로 설정
    
    # IP 및 포트 검증
    if not is_valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400
    if not is_valid_port(port):
        return jsonify({"error": "Invalid port number"}), 400

    command = f"sudo iptables -A INPUT -s {ip} -p {protocol} --dport {port} -j DROP"
    result = run_iptables_command(command)

    if result["error"]:
        return jsonify({"error": result["error"]}), 500
    
    return jsonify({"output": result["output"]})



# 규칙 삭제
@app.route('/iptables/delete_rule', methods=['POST'])
def delete_rule():
    data = request.json
    if not data or 'line_number' not in data or 'chain' not in data:
        return jsonify({"error": "Both line number and chain are required"}), 400

    line_number = data['line_number']
    chain = data['chain']

    command = f"sudo iptables -D {chain} {line_number}"
    result = run_iptables_command(command)

    if result["error"]:
        return jsonify({"error": result["error"]}), 500
    
    return jsonify({"output": result["output"]})
# ------------------------------------------------------------------- ip 차단 끝.


# ------------------------------------------------------------------- ip 허용 시작.

# IP 허용 규칙 추가 API
@app.route('/allow_ip', methods=['POST'])
def allow_ip():
    data = request.get_json()
    ip_address = data.get('ipAddress')
    port = data.get('portNumber')
    protocol = data.get('protocol', 'tcp')  # 기본 프로토콜은 TCP

    if not ip_address:
        return jsonify({'error': 'IP 주소가 필요합니다.'}), 400

    # iptables 명령어 생성 (포트와 프로토콜 포함 여부에 따라 달라집니다)
    if port:
        command = f"sudo iptables -A INPUT -p {protocol} --dport {port} -s {ip_address} -j ACCEPT"
    else:
        command = f"sudo iptables -A INPUT -s {ip_address} -j ACCEPT"

    # iptables 명령어 실행
    try:
        subprocess.run(command, shell=True, check=True)
        return jsonify({'message': 'IP 허용 규칙이 성공적으로 추가되었습니다.'})
    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'iptables 명령어 실행 중 오류 발생: {e}'}), 500

# ------------------------------------------------------------------- ip 허용 끝.


#--------------------------------------------------- NAT 시작.
# NAT pre 규칙 조회 API
@app.route('/nat/pre/rules', methods=['GET'])
def get_nat_pre_rules():
    result = list_pre_rules()
    if result['error']:
        return jsonify({"error": result['error']}), 500
    return jsonify({"output": result['output']}), 200

# NAT post 규칙 조회 API
@app.route('/nat/post/rules', methods=['GET'])
def get_nat_post_rules():
    result = list_post_rules()
    if result['error']:
        return jsonify({"error": result['error']}), 500
    return jsonify({"output": result['output']}), 200

# NAT 명령어 실행 API
@app.route('/nat/command', methods=['POST'])
def run_custom_nat_command():
    # 클라이언트가 보낸 명령어를 가져온다
    command_data = request.json
    command = command_data.get("command")
    
    if not command:
        return jsonify({"error": "No command provided"}), 400
    
    result = run_nat_command(command)
    
    if result['error']:
        return jsonify({"error": result['error']}), 500
    return jsonify({"output": result['output']}), 200


@app.route('/add_postrouting', methods=['POST'])
def add_postrouting():
    try:
        in_ip = request.form['inip']
        ex_ip = request.form['exip']
        inf = request.form['inf']

        # POSTROUTING 규칙 추가 명령어
        cmd = f"sudo iptables -t nat -A POSTROUTING -s {in_ip} -o {inf} -j SNAT --to-source {ex_ip}"
        subprocess.run(cmd, shell=True, check=True)
        
        return jsonify({'status': 'success', 'message': 'POSTROUTING 규칙이 추가되었습니다.'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/add_prerouting', methods=['POST'])
def add_prerouting():
    try:
        in_ip = request.form['inip']
        ex_ip = request.form['exip']
        in_port = request.form['inport']
        out_port = request.form['outport']
        protocol = request.form['protocol']

        # PREROUTING 규칙 추가 명령어
        cmd = f"sudo iptables -t nat -A PREROUTING -d {ex_ip} -p {protocol} --dport {out_port} -j DNAT --to-destination {in_ip}:{in_port}"
        subprocess.run(cmd, shell=True, check=True)
        
        return jsonify({'status': 'success', 'message': 'PREROUTING 규칙이 추가되었습니다.'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# NAT 규칙 삭제 - POSTROUTING
@app.route('/delete_postrouting', methods=['POST'])
def delete_postrouting():
    try:
        num = request.json.get('num')  # 사용자가 입력한 num 값 받기
        # iptables 명령어 실행 (POSTROUTING 규칙 삭제)
        cmd = f"sudo iptables -t nat -D POSTROUTING {num}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return jsonify({'success': True, 'message': 'POSTROUTING 규칙이 삭제되었습니다.'})
        else:
            return jsonify({'success': False, 'message': f'오류: {result.stderr}'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'서버 오류: {str(e)}'})

# NAT 규칙 삭제 - PREROUTING
@app.route('/delete_prerouting', methods=['POST'])
def delete_prerouting():
    try:
        num = request.json.get('num')  # 사용자가 입력한 num 값 받기
        # iptables 명령어 실행 (PREROUTING 규칙 삭제)
        cmd = f"sudo iptables -t nat -D PREROUTING {num}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return jsonify({'success': True, 'message': 'PREROUTING 규칙이 삭제되었습니다.'})
        else:
            return jsonify({'success': False, 'message': f'오류: {result.stderr}'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'서버 오류: {str(e)}'})

# 플로팅 아이피 인터페이스 설정
@app.route('/floting/interface/add', methods=['POST'])    
def floting_interface():
    try:
        ip = request.form['ip']
        interface = request.form['interface']
        cmd = f"sudo ip addr add {ip} dev {interface}"
        subprocess.run(cmd, shell=True, check=True)
        
        return jsonify({'status': 'success', 'message': '플로팅 IP 인터페이스 추가되었습니다.'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
#--------------------------------------------------- NAT 끝.

# --------------------------------------------------- 사용자 계정 시작.
# Helper function to run commands
def run_user_command2(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return {"output": result.stdout.decode('utf-8').strip()}
    except subprocess.CalledProcessError as e:
        return {"error": e.stderr.decode('utf-8').strip()}

# 직접 추가한 사용자 계정 리스트 조회하기.
@app.route('/user/list', methods=['GET'])
def user_list_get():
    result = list_user()
    if result["error"]:
        return jsonify({"error": result["error"]}), 500
    
    # 처리된 데이터를 output에 담아 보냅니다.
    return jsonify({"output": result["output"]})

# 디폴트 사용자 계정 리스트 조회하기.
@app.route('/user/list2', methods=['GET'])
def user_list2_get():
    result = list2_user()
    if result["error"]:
        return jsonify({"error": result["error"]}), 500
    
    # 처리된 데이터를 output에 담아 보냅니다.
    return jsonify({"output": result["output"]})

# 사용자 계정 추가
@app.route('/add_user', methods=['POST'])
def add_user_get():
    name = request.form['name']
    manual = request.form['manual']
    command = f"sudo useradd -m -c {manual} {name}"
    # adduser를 사용하여 계정 추가
    # command = f"sudo adduser {name} --gecos '{manual}' --disabled-password"
    result = run_user_command2(command)
    
    if "error" not in result:
        result["output"] = f"'{name}' 계정이 정상적으로 추가되었습니다."
    
    return jsonify(result)

# 사용자 계정 삭제
@app.route('/delete_user', methods=['POST'])
def delete_user():
    name = request.form['name']
    command = f"sudo userdel -r {name}"
    result = run_user_command2(command)
    
    if "error" not in result:
        result["output"] = f"'{name}' 계정이 정상적으로 삭제되었습니다."
    
    return jsonify(result)

# 패스워드 설정
@app.route('/set_password', methods=['POST'])
def set_password():
    name = request.form['name']
    password = request.form['password']
    command = f"echo '{name}:{password}' | sudo chpasswd"
    result = run_user_command2(command)
    
    if "error" not in result:
        result["output"] = f"'{name}' 계정의 패스워드가 설정되었습니다."
    
    return jsonify(result)

# --------------------------------------------------- 사용자 계정 끝.

#--------------------------------------------------- vpn 시작.
# VPN 디렉토리에 있는 파일 목록을 가져오는 함수
def get_vpn_files():
    vpn_dir = '/home/hallym/aegisai/vpn'  # vpn 디렉토리 경로를 입력하세요
    files = os.listdir(vpn_dir)
    return [{'num': idx + 1, 'client': file} for idx, file in enumerate(files)]

@app.route('/api/vpn-files')
def vpn_files():
    files = get_vpn_files()
    return jsonify(files)

# VPN 파일 다운로드 API
@app.route('/api/download-file/<filename>')
def download_file(filename):
    file_path = '/home/hallym/aegisai/vpn'
    try:
        return send_from_directory(file_path, filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    
# VPN 파일 삭제 API
@app.route('/api/delete-file/<filename>', methods=['DELETE'])
def delete_file(filename):
    file_path = os.path.join('/home/hallym/aegisai/vpn', filename)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({"message": "파일이 삭제되었습니다."}), 200
        else:
            return jsonify({"error": "File not found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route("/create-vpn", methods=["POST"])
def create_vpn():
    data = request.get_json()
    client_name = data.get("name")
    
    if not client_name or not client_name.isalnum():
        return jsonify({"message": "클라이언트 이름이 잘못 입력되었습니다."}), 400
    
    try:
        command = f"sudo ../auto-openvpn-install.sh 1 {client_name}"
        subprocess.run(command, shell=True, check=True)
        return jsonify({"message": f"VPN client '{client_name}' 생성되었습니다."})
    except subprocess.CalledProcessError as e:
        return jsonify({"message": f"Failed to create VPN client: {str(e)}"}), 500

#--------------------------------------------------- vpn 끝.

# -------------------------------------------------- ai 시작.

# 프로세스 ID를 저장할 변수
process = None

# 한계치 값 수정
@app.route('/update_ai_value', methods=['POST'])
def update_ai_value():
    ai_value = request.form.get('ai')
    if not ai_value:
        return jsonify({"error": "값이 비어 있습니다."}), 400

    # Flask 애플리케이션의 루트 디렉토리 경로 가져오기
    app_root = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(app_root, 'aitest.py')

    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        # 10번째 라인을 새 값으로 변경
        lines[9] = f"limit = {ai_value}\n"

        with open(file_path, 'w') as file:
            file.writelines(lines)

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 한계치 값을 읽어오는 함수
def get_current_limit():
    try:
        # aitest.py 파일의 절대 경로 설정
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'aitest.py')
        with open(script_path, 'r') as file:
            lines = file.readlines()
            # 10번째 줄 값 가져오기
            limit_value = lines[9].strip()
            return limit_value
    except Exception as e:
        return f"Error: {str(e)}"

# API: AI 모델 상태 및 한계치 값 반환
@app.route('/get_ai_status', methods=['GET'])
def get_ai_status():
    global process
    ai_status = "Running" if process is not None else "Stopped"
    current_limit = get_current_limit() + "%"  # 10번째 줄 값을 읽어옴
    
    return jsonify({
        "limit": current_limit,
        "status": ai_status
    })
    
# API: aitest.py 실행
@app.route('/start_ai', methods=['POST'])
def start_ai():
    global process
    if process is not None:
        return jsonify({"error": "AI 모델이 이미 실행 중입니다."}), 400

    try:
        # aitest.py 파일의 절대 경로 가져오기
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'aitest.py')
        process = subprocess.Popen(['python3', script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return jsonify({"success": "AI 모델이 성공적으로 실행되었습니다."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# API: 실행 중인 aitest.py 중지
@app.route('/stop_ai', methods=['POST'])
def stop_ai():
    global process
    if process is None:
        return jsonify({"error": "AI 모델이 실행 중이 아닙니다."}), 400

    try:
        # 프로세스 종료
        os.kill(process.pid, signal.SIGTERM)
        process = None
        return jsonify({"success": "AI 모델이 성공적으로 중지되었습니다."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/get_ai_ip_rules', methods=['GET'])
def get_ai_ip_rules():
    # iptables 명령어로 규칙 목록 가져오기
    result = list_ai_ip_rules()
    
    # 에러가 있을 경우 처리
    if result['error']:
        return jsonify({"error": result['error']}), 400
    
    # 규칙 목록을 파싱하여 반환
    ip_rules = parse_ai_ip_rules(result['output'])
    return jsonify(ip_rules)

def parse_ai_ip_rules(output):
    # iptables 규칙 목록을 파싱하여 리스트 형태로 변환
    rules = []
    for line in output.splitlines():
        # 데이터를 각 항목별로 분리
        parts = re.split(r'\s+', line)
        if len(parts) >= 10:
            rules.append({
                'num': parts[0],
                'pkts': parts[1],
                'bytes': parts[2],
                'target': parts[3],
                'prot': parts[4],
                'opt': parts[5],
                'in': parts[6],
                'out': parts[7],
                'source': parts[8],
                'destination': parts[9]
            })
    return rules

@app.route('/delete_ai_ip_rule/<int:rule_num>', methods=['DELETE'])
def delete_ai_ip_rule(rule_num):
    # iptables 명령어로 특정 규칙 삭제
    command = f"sudo iptables -D AI {rule_num}"
    result = run_iptables_command(command)
    
    if result['error']:
        return jsonify({"error": result['error']}), 400
    
    return jsonify({"message": "규칙 삭제 성공"}), 200
# -------------------------------------------------- ai 끝.

#--------------------------------------------------- 인터페이스 시작.

# 인터페이스 조회 API
@app.route('/inf/list', methods=['GET'])
def get_inf_list_get():
    result = list_inf()
    if result['error']:
        return jsonify({"error": result['error']}), 500
    return jsonify({"output": result['output']}), 200

#--------------------------------------------------- 인터페이스 끝.

# ------------------------------------------------------------------------------------------------------ 



if __name__ == '__main__':
    # 백그라운드에서 트래픽 데이터를 생성하는 쓰레드 실행
    start_network_traffic_thread()
    start_network_traffic_thread2()
    start_network_traffic_thread5()
    # ai_start_network_traffic_thread()

    # config.py 파일에서 설정 불러오기
    # app.config.from_pyfile("config.py")

    # 데이터베이스 엔진 생성
    # database = create_engine(app.config['DB_URL'], max_overflow=0)
    # app.database = database

    # Flask 애플리케이션 실행
    app.run('0.0.0.0', port=6001, debug=True)

    # 백그라운드에서 트래픽 데이터를 생성하는 쓰레드 실행
    socketio.run(app) # 순서 중요.
