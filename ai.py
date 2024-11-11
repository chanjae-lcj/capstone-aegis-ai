import subprocess
import re


# iptables 명령어 실행 함수
def run_iptables_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return {"output": result.stdout.decode(), "error": None}
    except subprocess.CalledProcessError as e:
        return {"output": None, "error": e.stderr.decode()}


# 허용된 규칙 목록 (INPUT 체인만, 포트와 IP 표시) 가져오기 함수
def list_ai_ip_rules():
    command = "sudo iptables -L AI -v -n --line-numbers"
    return run_iptables_command(command)