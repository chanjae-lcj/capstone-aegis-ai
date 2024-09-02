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
    # mysql db 연동
    # app.config.from_pyfile("config.py")
    # database = create_engine(app.config['DB_URL'], encoding='utf-8', max_overflow=0)
    # app.database = database

    app.run(debug=True) # 플라스크 처음 디폴트
    # app.run('0.0.0.0', port=5000, debug=True)

# 실헹 방법 : 그냥 오른쪽 위에 실행 버튼 누르기