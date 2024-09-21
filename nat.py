import subprocess
import re

# iptables nat 명령어 실행 함수
def run_nat_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return {"output": result.stdout.decode(), "error": None}
    except subprocess.CalledProcessError as e:
        return {"output": None, "error": e.stderr.decode()}

# 차단된 규칙 목록 (INPUT 체인만, 포트와 IP 표시) 가져오기 함수
def list_nat_rules():
    # INPUT 체인에서 IP와 포트 정보를 포함한 상세 규칙을 가져오는 명령어
    command = "sudo iptables -t nat -L -n -v"
    return run_nat_command(command)