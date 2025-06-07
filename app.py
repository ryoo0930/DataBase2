from flask import Flask, render_template, request, jsonify
import pymysql
from datetime import date, timedelta
import logging

app = Flask(__name__)
PER_PAGE = 12

VALID_SORT_COLUMNS = {
    'id': 'c.cve_id',
    'severity': 'FIELD(UPPER(c.severity), "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")',
    'date': 'c.published_date'
}

logging.basicConfig(level=logging.INFO)

def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',
        db='cve_db',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

@app.route('/api/stats')
def api_stats():
    conn = get_db_connection()
    stats = {}
    product_name = request.args.get('product')

    # product 파라미터가 있을 때만 동작하는 기본 로직은 유지
    if product_name:
        params = {'product': product_name}
        with conn.cursor() as cur:
            # 1. 심각도별 분포 (기존과 동일하나, product 파라미터 바인딩 방식만 정리)
            severity_sql = """
                SELECT UPPER(c.severity) AS severity, COUNT(*) AS count
                FROM cve AS c
                JOIN cve_product AS cp ON c.cve_id = cp.cve_id
                JOIN product AS p ON cp.product_id = p.product_id
                WHERE p.product_name = %(product)s
                GROUP BY severity
            """
            cur.execute(severity_sql, params)
            stats['severity_distribution'] = cur.fetchall()

            # ==================== 수정된 부분 시작 ====================
            # 2. CVE 등록 추이 (12개월, 0으로 채우기 기능 적용)
            chart_title = "최근 1년 등록 추이"
            
            # MySQL 8.0 이상에서 지원하는 RECURSIVE CTE를 사용하여 12개월 목록 생성
            trend_sql = """
                WITH RECURSIVE month_series (month_start) AS (
                    -- 11개월 전 첫날부터 시작
                    SELECT DATE_SUB(LAST_DAY(CURDATE()), INTERVAL 12 MONTH) + INTERVAL 1 DAY
                    UNION ALL
                    -- 다음 달을 계속 추가
                    SELECT month_start + INTERVAL 1 MONTH
                    FROM month_series
                    WHERE month_start + INTERVAL 1 MONTH <= CURDATE()
                )
                SELECT
                    -- YYYY-MM 형식으로 월 표시
                    DATE_FORMAT(m.month_start, '%%Y-%%m') AS `date`,
                    -- 해당 월의 CVE 개수를 세고, 없으면 0으로 표시
                    COALESCE(COUNT(c.cve_id), 0) AS `count`
                FROM
                    month_series m
                LEFT JOIN
                    (cve c
                    JOIN cve_product cp ON c.cve_id = cp.cve_id
                    JOIN product p ON cp.product_id = p.product_id)
                ON
                    p.product_name = %(product)s AND DATE_FORMAT(c.published_date, '%%Y-%%m') = DATE_FORMAT(m.month_start, '%%Y-%%m')
                GROUP BY
                    `date`
                ORDER BY
                    `date` DESC;
            """
            cur.execute(trend_sql, params)
            stats['daily_trend'] = cur.fetchall()
            stats['trend_chart_title'] = chart_title
            # ==================== 수정된 부분 끝 ====================

    conn.close()
    return jsonify(stats)


@app.route('/')
def index():
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    try:
        selected = request.args.get('filter', 'ALL').upper()
        search_q = request.args.get('search', '').strip()
        sort_by = request.args.get('sort_by', 'date')
        sort_order = request.args.get('sort_order', 'desc').lower()

        if sort_by not in VALID_SORT_COLUMNS:
            sort_by = 'date'
        if sort_order not in ['asc', 'desc']:
            sort_order = 'desc'

        try:
            page = max(1, int(request.args.get('page', '1')))
        except ValueError:
            page = 1
        offset = (page - 1) * PER_PAGE

        base_sql = """
            FROM cve AS c
            LEFT JOIN cve_product AS cp ON c.cve_id = cp.cve_id
            LEFT JOIN product      AS p  ON cp.product_id = p.product_id
            LEFT JOIN vendor       AS v  ON p.vendor_id = v.vendor_id
            WHERE 1=1
        """
        params = {}

        if selected != 'ALL':
            base_sql += " AND UPPER(c.severity) = %(sev)s"
            params['sev'] = selected

        if search_q:
            base_sql += " AND (LOWER(v.vendor_name) LIKE %(pat)s OR LOWER(p.product_name) LIKE %(pat)s)"
            params['pat'] = f"%{search_q.lower()}%"

        order_by_clause = f"ORDER BY {VALID_SORT_COLUMNS[sort_by]} {sort_order}"
        list_sql = (
            "SELECT "
            " c.cve_id, c.description, UPPER(c.severity) AS severity,"
            " COALESCE(c.cwe_id,'UNKNOWN') AS cwe_id,"
            " c.published_date AS pub_date,"
            " DATE_FORMAT(c.published_date,'%%Y-%%m-%%d') AS published_date,"
            " v.vendor_name, p.product_name "
            + base_sql + f" {order_by_clause} LIMIT {PER_PAGE+1} OFFSET {offset}"
        )

        count_sql = (
            "SELECT UPPER(c.severity) AS sev, COUNT(*) AS cnt "
            + base_sql + " AND c.published_date >= DATE_SUB(CURDATE(), INTERVAL 3 DAY) "
            " GROUP BY UPPER(c.severity)"
        )

        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(list_sql, params)
            rows = cur.fetchall()
            cves = rows[:PER_PAGE]
            has_next = len(rows) > PER_PAGE
            has_prev = page > 1

            cur.execute(count_sql, params)
            raw_counts = {r['sev']: r['cnt'] for r in cur.fetchall()}

        conn.close()

        today = date.today()
        three_days_ago = today - timedelta(days=3)
        for r in cves:
            r['is_recent'] = (r['pub_date'] >= three_days_ago)

        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
        counts = {sev: raw_counts.get(sev, 0) for sev in severities}
        total_count = sum(counts.values())

        if is_ajax:
            table_rows_html = render_template('partials/cve_table_rows.html', cves=cves)
            return jsonify({
                'html': table_rows_html,
                'has_prev': has_prev,
                'has_next': has_next,
                'counts': counts,
                'total_count': total_count
            })

        return render_template(
            'index.html',
            cves=cves,
            counts=counts,
            total_count=total_count,
            selected=selected,
            search_query=search_q,
            page=page,
            has_prev=has_prev,
            has_next=has_next,
            sort_by=sort_by,
            sort_order=sort_order
        )
    except Exception as e:
        app.logger.error(f"An error occurred: {e}", exc_info=True)
        if is_ajax:
            return jsonify({'error': '서버에서 오류가 발생했습니다.'}), 500
        else:
            return "An internal error occurred.", 500

if __name__ == '__main__':
    app.run(debug=True)