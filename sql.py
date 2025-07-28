import sqlite3
import mysql.connector
from flask import Flask, request, jsonify, render_template_string
import pymongo
from pymongo import MongoClient

app = Flask(__name__)

# Database configuration
DB_PATH = 'vulnerable_app.db'
MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'password',
    'database': 'testdb'
}

class VulnerableUserService:
    def __init__(self):
        self.db_path = DB_PATH

    # VULNERABLE: SQL Injection through string formatting
    def get_user_by_id(self, user_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # VULNERABLE: Direct string formatting
        query = "SELECT * FROM users WHERE id = %s" % user_id
        cursor.execute(query)
        
        result = cursor.fetchone()
        conn.close()
        return result

    # VULNERABLE: SQL Injection through f-string
    def authenticate_user(self, username, password):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # VULNERABLE: f-string interpolation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        
        user = cursor.fetchone()
        conn.close()
        return user is not None

    # VULNERABLE: SQL Injection through .format()
    def search_users(self, search_term):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # VULNERABLE: .format() method without parameterization
        query = "SELECT * FROM users WHERE username LIKE '{}%'".format(search_term)
        cursor.execute(query)
        
        results = cursor.fetchall()
        conn.close()
        return results

user_service = VulnerableUserService()

@app.route('/login', methods=['POST'])
def login():
    """VULNERABLE: SQL injection in login endpoint"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # VULNERABLE: Direct string concatenation
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = "SELECT id, username FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            return jsonify({"success": True, "user_id": user[0], "username": user[1]})
        else:
            return jsonify({"success": False, "message": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/users/search', methods=['GET'])
def search_users():
    """VULNERABLE: SQL injection in search functionality"""
    search_term = request.args.get('q', '')
    category = request.args.get('category', 'username')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # VULNERABLE: Dynamic column name and value insertion
    query = f"SELECT * FROM users WHERE {category} LIKE '%{search_term}%'"
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """VULNERABLE: SQL injection in URL parameter"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # VULNERABLE: Direct parameter insertion
    query = "SELECT id, username, email, created_at FROM users WHERE id = " + str(user_id)
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            return jsonify({
                "id": user[0],
                "username": user[1], 
                "email": user[2],
                "created_at": user[3]
            })
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/reports', methods=['POST'])
def generate_report():
    """VULNERABLE: SQL injection in reporting functionality"""
    data = request.get_json()
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    user_type = data.get('user_type', 'all')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # VULNERABLE: Multiple injection points
    base_query = "SELECT * FROM users WHERE created_at >= '{}' AND created_at <= '{}'".format(start_date, end_date)
    
    if user_type != 'all':
        # VULNERABLE: Additional injection point
        base_query += f" AND user_type = '{user_type}'"
    
    try:
        cursor.execute(base_query)
        results = cursor.fetchall()
        return jsonify({"report_data": results, "total_records": len(results)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# VULNERABLE: MySQL injection example
@app.route('/mysql/users', methods=['GET'])
def mysql_get_users():
    """VULNERABLE: SQL injection with MySQL connector"""
    department = request.args.get('dept', '')
    status = request.args.get('status', 'active')
    
    try:
        connection = mysql.connector.connect(**MYSQL_CONFIG)
        cursor = connection.cursor()
        
        # VULNERABLE: String interpolation in MySQL query
        query = f"SELECT id, name, email FROM employees WHERE department = '{department}' AND status = '{status}'"
        cursor.execute(query)
        
        results = cursor.fetchall()
        return jsonify({"employees": results})
        
    except mysql.connector.Error as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# VULNERABLE: Dynamic table name injection
@app.route('/admin/data', methods=['GET'])
def get_admin_data():
    """VULNERABLE: Table name injection"""
    table_name = request.args.get('table')
    limit = request.args.get('limit', '10')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # VULNERABLE: Dynamic table name without validation
    query = f"SELECT * FROM {table_name} LIMIT {limit}"
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        return jsonify({"data": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# VULNERABLE: NoSQL injection example (MongoDB)
@app.route('/mongo/users', methods=['POST'])
def mongo_find_users():
    """VULNERABLE: NoSQL injection in MongoDB"""
    data = request.get_json()
    username = data.get('username')
    
    try:
        client = MongoClient('mongodb://localhost:27017/')
        db = client['vulnerable_app']
        collection = db['users']
        
        # VULNERABLE: Direct user input in MongoDB query
        query = eval(f"{{\"username\": \"{username}\"}}")
        users = list(collection.find(query))
        
        return jsonify({"users": users})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# VULNERABLE: SQL injection with execute() using % operator
@app.route('/legacy/search', methods=['GET'])
def legacy_search():
    """VULNERABLE: Legacy style SQL injection"""
    search_query = request.args.get('q')
    table = request.args.get('table', 'users')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # VULNERABLE: % operator for string formatting
    sql = "SELECT * FROM %s WHERE name LIKE '%%%s%%'" % (table, search_query)
    
    try:
        cursor.execute(sql)
        results = cursor.fetchall()
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
