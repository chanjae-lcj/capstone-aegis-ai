from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from sqlalchemy import create_engine
import pam
import os
import json
import psutil   # cpu 관련 라이브러리
from firewall import is_valid_ip, is_valid_port, run_iptables_command, list_iptables_rules
from bgp import delete_bgp_protocol, add_bgp_protocol, enable_bgp_protocol,list_bgp_protocols,disable_bgp_protocol  # bgp.py 모듈을 import
from static_routes import add_static_route, delete_static_route, list_routes  # static_routes 모듈을 import
from nat import list_nat_rules, run_nat_command
from flask_socketio import SocketIO
import threading
import time
import subprocess

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
        return jsonify(success=False, message="Invalid credentials. Please try again.")


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
    return render_template("bgp.html")

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
    return render_template("routes.html")

# ------------------- gh.w -----------------------  static

# ----------------- 네트워크 정보 -------------------  네트워크 정보 시작
# 이전 네트워크 상태 저장
previous_data = psutil.net_io_counters(pernic=True)

# 네트워크 그래프
def get_network_traffic():
    """실제 네트워크 사용량을 계산하여 반환"""
    global previous_data
    current_data = psutil.net_io_counters(pernic=True)
    traffic_data = {}

    for interface, counters in current_data.items():
        if interface in previous_data:
            previous_counters = previous_data[interface]
            traffic_data[interface] = {
                'in': counters.bytes_recv - previous_counters.bytes_recv,  # 받은 데이터 양 (IN)
                'out': counters.bytes_sent - previous_counters.bytes_sent   # 보낸 데이터 양 (OUT)
            }
        else:
            traffic_data[interface] = {
                'in': 0,
                'out': 0
            }

    previous_data = current_data
    return traffic_data

# 네트워크 테이블
def get_network_traffic2():
    """네트워크 사용량을 반환"""
    traffic_data2 = {}
    counters = psutil.net_io_counters(pernic=True)
    for interface, data in counters.items():
        traffic_data2[interface] = {
            'bytes_sent': data.bytes_sent,
            'bytes_recv': data.bytes_recv,
            'packets_sent': data.packets_sent,
            'packets_recv': data.packets_recv,
            'errin': data.errin,
            'errout': data.errout,
            'dropin': data.dropin,
            'dropout': data.dropout
        }
    return traffic_data2

def background_thread():
    """네트워크 사용량을 실시간으로 보내는 백그라운드 스레드"""
    while True:
        traffic_data = get_network_traffic()
        traffic_data2 = get_network_traffic2()
        socketio.emit('network_data', traffic_data)
        socketio.emit('network_data2', traffic_data2)
        time.sleep(1)

@socketio.on('connect')
def connect():
    """클라이언트가 접속하면 백그라운드 스레드 시작"""
    threading.Thread(target=background_thread).start()
# ----------------- 네트워크 정보 -------------------  네트워크 정보 끝



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


@app.route('/nat/list', methods=['GET'])
def nat_list():
    result = list_nat_rules()
    
    if result["error"]:
        return jsonify({"error": result["error"]}), 500
    
    return jsonify({"output": result["output"]})

# -------------------- gh.w --------------------------


# 차단된 IP, 포트 목록 가져오기
@app.route('/iptables/list', methods=['GET'])
def list_rules():
    result = list_iptables_rules()
    
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
# ----------------------------------------------------------------------------


#--------------------------------------------------- NAT 시작.
# NAT 규칙 조회 API
@app.route('/nat/rules', methods=['GET'])
def get_nat_rules():
    result = list_nat_rules()
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
        in_port = request.form['inport']
        out_port = request.form['outport']
        protocol = request.form['protocol']

        # POSTROUTING 규칙 추가 명령어
        cmd = f"sudo iptables -t nat -A POSTROUTING -s {in_ip} -p {protocol} --sport {in_port} -j SNAT --to-source {ex_ip}:{out_port}"
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
#--------------------------------------------------- NAT 끝.



# ------------------------------------------------------------------------------------------------------ 



if __name__ == '__main__':
    # config.py 파일에서 설정 불러오기
    app.config.from_pyfile("config.py")

    # 데이터베이스 엔진 생성
    database = create_engine(app.config['DB_URL'], max_overflow=0)
    app.database = database

    # Flask 애플리케이션 실행
    app.run('0.0.0.0', port=6001, debug=True)
