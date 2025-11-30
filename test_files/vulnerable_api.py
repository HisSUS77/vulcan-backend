from flask import Flask, request, jsonify, make_response
import sqlite3
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'  # Weak secret key

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            api_key TEXT
        )
    ''')
    
    # Add sample users
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin', 'admintoken123')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user1', 'password1', 'user', 'usertoken123')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (3, 'user2', 'password2', 'user', 'usertoken456')")
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            item TEXT,
            quantity INTEGER,
            price REAL
        )
    ''')
    
    # Add sample orders
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (101, 1, 'Laptop', 1, 1200.00)")
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (102, 2, 'Mouse', 2, 25.50)")
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (103, 3, 'Keyboard', 1, 75.00)")
    
    conn.commit()
    conn.close()

# Token validation decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            token = token.split(' ')[1]  # Remove 'Bearer ' prefix
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = get_user_by_id(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

def get_user_by_id(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # SQL Injection vulnerability
    user = cursor.fetchone()
    conn.close()
    return user

# API endpoints
@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{auth['username']}' AND password = '{auth['password']}'")  # SQL Injection vulnerability
    user = cursor.fetchone()
    conn.close()
    
    if user:
        token = jwt.encode({
            'user_id': user[0],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'])
        
        return jsonify({'token': token})
    
    return make_response('Could not verify', 403, {'WWW-Authenticate': 'Basic realm="Login required!"'})

@app.route('/user', methods=['GET'])
@token_required
def get_user(current_user):
    user_data = {
        'id': current_user[0],
        'username': current_user[1],
        'role': current_user[3]
    }
    return jsonify(user_data)

@app.route('/users', methods=['GET'])
def get_all_users():
    # No authentication required - Broken Access Control
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    
    result = []
    for user in users:
        result.append({
            'id': user[0],
            'username': user[1],
            'role': user[3]
        })
    
    return jsonify(result)

@app.route('/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    # No authorization check - BOLA vulnerability
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")  # SQL Injection vulnerability
    order = cursor.fetchone()
    conn.close()
    
    if order:
        return jsonify({
            'id': order[0],
            'user_id': order[1],
            'item': order[2],
            'quantity': order[3],
            'price': order[4]
        })
    
    return jsonify({'message': 'Order not found'}), 404

@app.route('/orders', methods=['POST'])
@token_required
def create_order(current_user):
    data = request.json
    
    # Mass Assignment vulnerability - accepting any field
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO orders (user_id, item, quantity, price) VALUES ({current_user[0]}, '{data['item']}', {data['quantity']}, {data['price']})")
    conn.commit()
    order_id = cursor.lastrowid
    conn.close()
    
    return jsonify({'message': 'Order created', 'order_id': order_id}), 201

@app.route('/admin', methods=['GET'])
def admin_panel():
    # No authentication - Security Misconfiguration
    return jsonify({'message': 'Welcome to Admin Panel', 'users': '/users', 'orders': '/orders'})

@app.route('/fetch', methods=['GET'])
def fetch_url():
    # SSRF vulnerability
    url = request.args.get('url')
    if not url:
        return jsonify({'message': 'URL parameter is required'}), 400
    
    # In a real app, this would fetch the URL, but we'll simulate
    return jsonify({'message': f'Fetched content from {url}', 'status': 'success'})

@app.route('/debug', methods=['GET'])
def debug_info():
    # Exposes sensitive debug information
    return jsonify({
        'app_version': '1.0.0',
        'debug_mode': True,
        'database': 'users.db',
        'secret_key': app.config['SECRET_KEY']
    })

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
