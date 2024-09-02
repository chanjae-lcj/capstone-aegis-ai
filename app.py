from flask import Flask, render_template, url_for
from sqlalchemy import create_engine

app = Flask(__name__)

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/login')
def login():
    return render_template("login.html")

if __name__ == '__main__':
    # config.py 파일에서 설정 불러오기
    app.config.from_pyfile("config.py")

    # 데이터베이스 엔진 생성
    database = create_engine(app.config['DB_URL'], max_overflow=0)
    app.database = database

    # Flask 애플리케이션 실행
    app.run('0.0.0.0', port=5000, debug=True)

# 실헹 방법 : 그냥 오른쪽 위에 실행 버튼 누르기