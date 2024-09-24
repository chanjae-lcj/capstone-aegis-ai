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
    # command = "sudo iptables -t nat -L -n -v"
    command = "sudo iptables -t nat -L -v -n --line-number"
    return run_nat_command(command)


# NAT 규칙 추가 함수
# def add_port_forwarding_rule(in_ip, ex_ip, in_port, out_port, protocol, rule_type):
#     try:
#         if rule_type == 'postrouting':
#             # POSTROUTING 규칙 추가
#             cmd = f"sudo iptables -t nat -A POSTROUTING -s {in_ip} -p {protocol} --sport {in_port} -j SNAT --to-source {ex_ip}:{out_port}"
#         else:
#             # PREROUTING 규칙 추가
#             cmd = f"sudo iptables -t nat -A PREROUTING -p {protocol} --dport {out_port} -j DNAT --to-destination {in_ip}:{in_port}"

#         process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#         stdout, stderr = process.communicate()

#         if process.returncode != 0:
#             return {'status': 'error', 'message': stderr.decode('utf-8')}

#         return {'status': 'success', 'message': f'Rule added successfully!'}

#     except Exception as e:
#         return {'status': 'error', 'message': str(e)}