import subprocess
import re


# user 명령어 실행 함수
def run_user_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return {"output": result.stdout.decode(), "error": None}
    except subprocess.CalledProcessError as e:
        return {"output": None, "error": e.stderr.decode()}
    

# 사용자 계정 리스트 조회
def list_user():
    #command = "cat /etc/passwd"
    command ="awk -F: '$3 >= 1000 { print $1, $3, $4, $5, $6, $7 }' /etc/passwd"
    return run_user_command(command)


# 사용자 계정 리스트 조회
def list2_user():
    command = "cat /etc/passwd"
    return run_user_command(command)


# 사용자 계정 추가
def add_user(name):
    command ="sudo useradd -m {name}"
    return run_user_command(command)


# 사용자 계정 삭제
def delete_user(name):
    command ="sudo userdel -r {name}"
    return run_user_command(command)


# 패스워드 설정
def pass_user(name, passWd):
    command1 ="sudo passwd {name}"
    run_user_command(command1)
    command2 ="{pass}"
    run_user_command(command2)
    command3 ="{pass}"
    run_user_command(command3)


