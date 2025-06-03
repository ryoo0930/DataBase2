from flask import Flask, render_template, request
import pymysql
from datetime import date, timedelta

app = Flask(__name__)
PER_PAGE = 12  # 한 페이지에 표시할 CVE 개수

def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',   # 실제 비밀번호로 변경
        db='cve_db',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

@app.route('/')
def index():
    # 1) 파라미터 취합
    selected   = request.args.get('filter', 'ALL').upper()
    search_q   = request.args.get('search', '').strip()
    try:
        page = max(1, int(request.args.get('page', '1')))
    except ValueError:
        page = 1
    offset = (page - 1) * PER_PAGE

    # 2) 기본 FROM/WHERE 절
    base_sql = """
        FROM cve AS c
        LEFT JOIN cve_product AS cp ON c.cve_id = cp.cve_id
        LEFT JOIN product      AS p  ON cp.product_id = p.product_id
        LEFT JOIN vendor       AS v  ON p.vendor_id = v.vendor_id
        WHERE 1=1
    """
    params = {}

    # Severity 필터
    if selected != 'ALL':
        base_sql += " AND UPPER(c.severity) = %(sev)s"
        params['sev'] = selected

    # Vendor/Product 검색 필터
    if search_q:
        base_sql += " AND (LOWER(v.vendor_name) LIKE %(pat)s OR LOWER(p.product_name) LIKE %(pat)s)"
        params['pat'] = f"%{search_q.lower()}%"

    # 3) CVE 리스트 쿼리 (페이징 포함)
    list_sql = (
        "SELECT "
        " c.cve_id,"
        " c.description,"
        " UPPER(c.severity) AS severity,"
        " COALESCE(c.cwe_id,'UNKNOWN') AS cwe_id,"
        " c.published_date AS pub_date,"
        " DATE_FORMAT(c.published_date,'%%Y-%%m-%%d') AS published_date,"
        " v.vendor_name,"
        " p.product_name "
        + base_sql +
        " ORDER BY c.published_date DESC "
        f" LIMIT {PER_PAGE+1} OFFSET {offset}"
    )

    # 4) 심각도별 “최근 3일” 카운트 쿼리
    count_sql = (
        "SELECT UPPER(c.severity) AS sev, COUNT(*) AS cnt "
        + base_sql +
        " AND c.published_date >= DATE_SUB(CURDATE(), INTERVAL 3 DAY) "
        " GROUP BY UPPER(c.severity)"
    )

    conn = get_db_connection()
    with conn.cursor() as cur:
        # 4-1) 리스트 조회
        cur.execute(list_sql, params)
        rows = cur.fetchall()
        cves = rows[:PER_PAGE]
        has_next = len(rows) > PER_PAGE
        has_prev = page > 1

        # 4-2) 심각도별 카운트 조회
        cur.execute(count_sql, params)
        raw_counts = {r['sev']: r['cnt'] for r in cur.fetchall()}

    conn.close()

    # 5) 최근 3일 플래그 추가
    today = date.today()
    three_days_ago = today - timedelta(days=3)
    for r in cves:
        r['is_recent'] = (r['pub_date'] >= three_days_ago)

    # 6) 템플릿으로 전달할 카운트 정리
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
    counts = {sev: raw_counts.get(sev, 0) for sev in severities}
    total_count = sum(counts.values())

    return render_template(
        'index.html',
        cves=cves,
        counts=counts,
        total_count=total_count,
        selected=selected,
        search_query=search_q,
        page=page,
        has_prev=has_prev,
        has_next=has_next
    )

if __name__ == '__main__':
    app.run(debug=True)
