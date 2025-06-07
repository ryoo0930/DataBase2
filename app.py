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

    if product_name:
        params = {'product': product_name}
        with conn.cursor() as cur:
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

            chart_title = "최근 1년 등록 추이"
            
            trend_sql = """
                WITH RECURSIVE month_series (month_start) AS (
                    SELECT DATE_SUB(LAST_DAY(CURDATE()), INTERVAL 12 MONTH) + INTERVAL 1 DAY
                    UNION ALL
                    SELECT month_start + INTERVAL 1 MONTH
                    FROM month_series
                    WHERE month_start + INTERVAL 1 MONTH <= CURDATE()
                )
                SELECT
                    DATE_FORMAT(m.month_start, '%%Y-%%m') AS `date`,
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

        # 1. 카운트 계산을 위한 SQL 생성 (검색어만 반영)
        count_base_sql = """
            FROM cve AS c
            LEFT JOIN cve_product AS cp ON c.cve_id = cp.cve_id
            LEFT JOIN product      AS p  ON cp.product_id = p.product_id
            LEFT JOIN vendor       AS v  ON p.vendor_id = v.vendor_id
            WHERE 1=1
        """
        count_params = {}
        if search_q:
            count_base_sql += " AND (LOWER(v.vendor_name) LIKE %(pat)s OR LOWER(p.product_name) LIKE %(pat)s)"
            count_params['pat'] = f"%{search_q.lower()}%"
        
        count_sql = (
            "SELECT UPPER(c.severity) AS sev, COUNT(*) AS cnt "
            + count_base_sql + " AND c.published_date >= DATE_SUB(CURDATE(), INTERVAL 3 DAY) "
            " GROUP BY UPPER(c.severity)"
        )

        # 2. 테이블 목록을 위한 SQL 생성 (검색어 + 심각도 필터 모두 반영)
        list_base_sql = count_base_sql
        list_params = count_params.copy()
        if selected != 'ALL':
            list_base_sql += " AND UPPER(c.severity) = %(sev)s"
            list_params['sev'] = selected

        order_by_clause = f"ORDER BY {VALID_SORT_COLUMNS[sort_by]} {sort_order}"
        list_sql = (
            "SELECT "
            " c.cve_id, c.description, UPPER(c.severity) AS severity,"
            " COALESCE(c.cwe_id,'UNKNOWN') AS cwe_id,"
            " c.published_date AS pub_date,"
            " DATE_FORMAT(c.published_date,'%%Y-%%m-%%d') AS published_date,"
            " v.vendor_name, p.product_name "
            + list_base_sql + f" {order_by_clause} LIMIT {PER_PAGE+1} OFFSET {offset}"
        )

        conn = get_db_connection()
        with conn.cursor() as cur:
            # 목록은 list_sql과 list_params 사용
            cur.execute(list_sql, list_params)
            rows = cur.fetchall()
            cves = rows[:PER_PAGE]
            has_next = len(rows) > PER_PAGE
            has_prev = page > 1

            # 카운트는 count_sql과 count_params 사용
            cur.execute(count_sql, count_params)
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