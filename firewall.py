import subprocess
import re

# IP 주소 및 서브넷 마스크 유효성 검사 (CIDR 지원)
def is_valid_ip(ip):
    # CIDR 표기법도 허용 (예: 192.168.1.0/24)
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/\d{1,2})?$")
    return pattern.match(ip) is not None

# 포트 번호 유효성 검사
def is_valid_port(port):
    return port.isdigit() and 1 <= int(port) <= 65535

# iptables 명령어 실행 함수
def run_iptables_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return {"output": result.stdout.decode(), "error": None}
    except subprocess.CalledProcessError as e:
        return {"output": None, "error": e.stderr.decode()}

# 차단된 규칙 목록 (INPUT 체인만, 포트와 IP 표시) 가져오기 함수
def list_iptables_rules():
    # INPUT 체인에서 IP와 포트 정보를 포함한 상세 규칙을 가져오는 명령어
    command = "sudo iptables -L INPUT -v -n --line-numbers"
    return run_iptables_command(command)
