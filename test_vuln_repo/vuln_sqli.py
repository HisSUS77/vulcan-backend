# vuln_sqli.py - SQL Injection vulnerabilities
import sqlite3
import pymysql
from flask import Flask, request

app = Flask(__name__)

def get_user(username, password):
    """Vulnerable: SQL injection via string concatenation"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # BAD: Direct string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()

def search_products(search_term):
    """Vulnerable: SQL injection via f-string"""
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    # BAD: f-string with user input
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
    return cursor.fetchall()

@app.route('/login', methods=['POST'])
def login():
    """Vulnerable login endpoint"""
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    user = get_user(username, password)
    if user:
        return {"status": "success", "user": user[0]}
    return {"status": "failed"}

@app.route('/search')
def search():
    """Vulnerable search endpoint"""
    query = request.args.get('q', '')
    results = search_products(query)
    return {"results": results}

def admin_query(user_id):
    """Vulnerable: SQL injection with MySQL"""
    conn = pymysql.connect(host='localhost', user='admin', password='password', database='app')
    cursor = conn.cursor()
    # BAD: String formatting
    sql = "SELECT * FROM admin_users WHERE id = %s" % user_id
    cursor.execute(sql)
    return cursor.fetchone()

if __name__ == '__main__':
    app.run(debug=True)
