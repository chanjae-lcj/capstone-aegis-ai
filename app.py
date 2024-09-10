from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from sqlalchemy import create_engine
import pam
import os
import json

app = Flask(__name__)
app.secret_key = '' # 세션을 위한 비밀 키


# PAM 객체 생성
pam_auth = pam.pam()


# 루트 접속시
@app.route('/')
def login():
    if 'username' in session:
        return redirect(url_for('home'))
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


@app.route('/dashboard')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("index.html", username=username)


# 차트
@app.route('/dashboard/charts')
def charts():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return render_template("charts.html", username=username)

# 연습 1
@app.route('/dashboard/bbb')
def practice1():
    return render_template("bbb.html")

# 연습 2
@app.route('/dashboard/aaa')
def practice2():
    return render_template("aaa.html")
    


if __name__ == '__main__':
    # config.py 파일에서 설정 불러오기
    app.config.from_pyfile("config.py")

    # 데이터베이스 엔진 생성
    database = create_engine(app.config['DB_URL'], max_overflow=0)
    app.database = database

    # Flask 애플리케이션 실행
    app.run('0.0.0.0', port=5000, debug=True)
