import subprocess
from flask import jsonify

# 정적 라우팅 추가 함수
def add_static_route(destination, gateway, interface=None):
    if interface:
        command = f"sudo ip route add {destination} via {gateway} dev {interface}"
    else:
        command = f"sudo ip route add {destination} via {gateway}"
    
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    if result.returncode == 0:
        return {"message": "Static route added successfully."}, 200
    else:
        return {"error": result.stderr.decode('utf-8')}, 500

# 정적 라우팅 삭제 함수
def delete_static_route(destination):
    command = f"sudo ip route del {destination}"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    if result.returncode == 0:
        return {"message": "Static route deleted successfully."}, 200
    else:
        return {"error": result.stderr.decode('utf-8')}, 500

# 현재 라우팅 테이블 조회 함수
def list_routes():
    command = "route -4"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    if result.returncode == 0:
        routes = result.stdout.decode('utf-8').splitlines()[2:]  # 헤더 제거
        return {"routes": routes}, 200
    else:
        return {"error": result.stderr.decode('utf-8')}, 500
