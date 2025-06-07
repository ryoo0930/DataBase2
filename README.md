# JBNU25 데이터베이스 프로젝트

이 문서는 JBNU25 데이터베이스 프로젝트를 로컬 환경에서 설정하고 실행하는 방법을 안내합니다.

---

## 📚 프로젝트 소개

본 프로젝트는 **Flask**와 **MySQL**을 사용하여 CVE(Common Vulnerabilities and Exposures) 정보를 조회하고 필터링하는 웹 애플리케이션입니다.
사용자들은 이 애플리케이션을 통해 특정 조건에 맞는 CVE 정보를 쉽게 찾아볼 수 있습니다.

---

## 🛠️ 기술 스택

* **백엔드:** Python (Flask)
* **데이터베이스:** MySQL
* **프론트엔드:** HTML, CSS

---

## ⚙️ 로컬 환경 설정

### 1. 사전 준비

* **Python 3** 설치: [python.org](https://www.python.org/)
* **MySQL** 설치: [MySQL Community Server](https://dev.mysql.com/downloads/mysql/)

### 2. 프로젝트 클론 및 가상 환경 설정

```Bash
# 프로젝트를 클론합니다.
git clone [https://github.com/ryoo0930/jbnu25_database.git](https://github.com/ryoo0930/jbnu25_database.git)

# 프로젝트 디렉토리로 이동합니다.
cd jbnu25_database

# 가상 환경을 생성합니다.
python -m venv venv

# 가상 환경을 활성화합니다.
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

### 3. 필요 패키지 설치

requirements.txt 파일에 명시된 패키지들을 설치합니다.
```Bash
pip install -r requirements.txt
```

### 4. 데이터베이스 설정

* **MySQL**에 접속하여 새로운 데이터베이스를 생성합니다.
```SQL
CREATE DATABASE cve_db;
```
* **Export.sql** 파일을 사용하여 생성한 데이터베이스에 테이블과 데이터를 가져옵니다(import).
```Bash
# mysql -u [사용자명] -p [데이터베이스명] < Export.sql
mysql -u root -p cve_db < Export.sql
```

### 5. Flask 환경 변수 설정

app.py 파일에서 데이터베이스 연결 정보를 로컬 환경에 맞게 수정해야 합니다.
app.py 파일의 다음 부분을 수정합니다.
```Python
# app.py

# ... (생략) ...

# Database connection
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'YOUR_MYSQL_USERNAME' # 본인의 MySQL 사용자 이름으로 변경
app.config['MYSQL_PASSWORD'] = 'YOUR_MYSQL_PASSWORD' # 본인의 MySQL 비밀번호로 변경
app.config['MYSQL_DB'] = 'cve_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# ... (생략) ...
```

---

## ▶️ 애플리케이션 실행

다음 명령어를 터미널에 입력하여 Flask 개발 서버를 실행합니다.
```Bash
flask run
```
서버가 정상적으로 실행되면, 웹 브라우저에서 http://127.0.0.1:5000 주소로 접속하여 애플리케이션을 확인할 수 있습니다.
