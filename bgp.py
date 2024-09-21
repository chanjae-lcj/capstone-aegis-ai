import subprocess

BIRD_CONFIG_FILE = '/etc/bird/bird.conf'

# BIRD 설정을 수정하는 함수
def modify_bird_config(new_config):
    try:
        with open(BIRD_CONFIG_FILE, 'a') as f:  # 파일을 append 모드로 열기
            f.write(new_config)
        
        result = subprocess.run(['sudo', 'birdc', 'configure'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return "BIRD configuration reloaded successfully " + BIRD_CONFIG_FILE
        else:
            return f"Error: {result.stderr.decode('utf-8')}"
    except Exception as e:
        return f"Exception: {str(e)}"

# BGP 프로토콜 활성화
def enable_bgp_protocol(protocol_name):
    try:
        result = subprocess.run(['sudo', 'birdc', 'enable', protocol_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return {"message": f"Protocol {protocol_name} enabled successfully."}, 200
        else:
            return {"error": result.stderr.decode('utf-8')}, 500
    except Exception as e:
        return {"error": str(e)}, 500

# BGP 프로토콜 비활성화
def disable_bgp_protocol(protocol_name):
    try:
        result = subprocess.run(['sudo', 'birdc', 'disable', protocol_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return {"message": f"Protocol {protocol_name} disabled successfully."}, 200
        else:
            return {"error": result.stderr.decode('utf-8')}, 500
    except Exception as e:
        return {"error": str(e)}, 500

# BIRD 설정 파일에서 특정 BGP 프로토콜을 삭제하는 함수
def delete_bgp_protocol(protocol_name):
    try:
        # 설정 파일을 읽기
        with open(BIRD_CONFIG_FILE, 'r') as f:
            lines = f.readlines()
        
        # 특정 프로토콜을 찾고 제외
        new_lines = []
        in_protocol_block = False

        for line in lines:
            if f"protocol bgp {protocol_name}" in line:
                in_protocol_block = True  # 시작을 찾음
            if in_protocol_block and '}' in line:
                in_protocol_block = False  # 끝나는 부분
                continue  # 블록을 제외
            if not in_protocol_block:
                new_lines.append(line)  # 제외되지 않는 내용은 다시 추가

        # 새로운 설정 파일을 작성
        with open(BIRD_CONFIG_FILE, 'w') as f:
            f.writelines(new_lines)

        # BIRD 재구성
        result = subprocess.run(['sudo', 'birdc', 'configure'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return {"message": f"Protocol {protocol_name} deleted successfully."}, 200
        else:
            return {"error": result.stderr.decode('utf-8')}, 500
    except Exception as e:
        return {"error": str(e)}, 500

# 새로운 BGP 프로토콜 추가
def add_bgp_protocol(protocol_name, neighbor_ip, local_as, neighbor_as, filter_option, custom_filter):
    # 기본 필터 설정
    if filter_option == "import_all":
        import_filter = "import all;"
        export_filter = "export all;"
    elif filter_option == "import_none":
        import_filter = "import none;"
        export_filter = "export none;"
    elif filter_option == "custom_filter" and custom_filter:
        import_filter = f"import filter {{ {custom_filter} }};"
        export_filter = "export all;"  # 필터링 조건에 따라 다르게 설정 가능
    else:
        return {"error": "Invalid filter option or custom filter"}, 400

    # BGP 설정 구성
    new_bgp_config = f"""
protocol bgp {protocol_name} {{
    local as {local_as};
    neighbor {neighbor_ip} as {neighbor_as};
    {import_filter}
    {export_filter}
}}
"""

    # 설정 파일 수정
    result = modify_bird_config(new_bgp_config)
    if "Error" in result:
        return {"error": result}, 500
    return {"message": "BGP protocol added successfully."}, 200


# BGP 프로토콜 리스트 가져오기
def list_bgp_protocols():
    try:
        result = subprocess.run(['sudo', 'birdc', 'show', 'protocols'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            protocols = result.stdout.decode('utf-8').splitlines()
            return {"protocols": protocols}, 200
        else:
            return {"error": result.stderr.decode('utf-8')}, 500
    except Exception as e:
        return {"error": str(e)}, 500
