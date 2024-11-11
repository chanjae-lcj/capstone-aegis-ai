import subprocess
import re


# inf 리스트 명령어 실행 함수
def run_inf_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return {"output": result.stdout.decode(), "error": None}
    except subprocess.CalledProcessError as e:
        return {"output": None, "error": e.stderr.decode()}


# 인터페이스 목록 조회
def list_inf():
    command = "ifconfig"
    return run_inf_command(command)

