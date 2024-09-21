import subprocess

# BGP 프로토콜 삭제
def delete_bgp_protocol(protocol_name):
    try:
        result = subprocess.run(['birdc', 'disable', protocol_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return f"Protocol {protocol_name} disabled successfully."
        else:
            return f"Error: {result.stderr.decode('utf-8')}"
    except Exception as e:
        return str(e)

# 새로운 BGP 프로토콜 추가
def add_bgp_protocol(protocol_name, neighbor_ip, local_as, neighbor_as):
    new_bgp_config = f"""
protocol bgp {protocol_name} {{
    local as {local_as};
    neighbor {neighbor_ip} as {neighbor_as};
    import all;
    export all;
}}
"""
    return modify_bird_config(new_bgp_config)

# BGP 프로토콜 수정 (disable -> enable)
def enable_bgp_protocol(protocol_name):
    try:
        result = subprocess.run(['birdc', 'enable', protocol_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return f"Protocol {protocol_name} enabled successfully."
        else:
            return f"Error: {result.stderr.decode('utf-8')}"
    except Exception as e:
        return str(e)

# BGP 프로토콜 삭제 실행 예시
print(delete_bgp_protocol("bgp1"))

# 새로운 BGP 프로토콜 추가 실행 예시
print(add_bgp_protocol("bgp1", "192.168.1.2", 65000, 65001))

# BGP 프로토콜 활성화 실행 예시
print(enable_bgp_protocol("bgp1"))
