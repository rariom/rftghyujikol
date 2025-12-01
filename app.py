from flask import Flask, request, jsonify
import psycopg2
from flask_bcrypt import Bcrypt
import jwt
import datetime
import os
from functools import wraps
from psycopg2.extras import RealDictCursor # Используем для получения данных в виде словарей

# =========================================================================
# 1. КОНФИГУРАЦИЯ
# =========================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_super_secure_key_12345') 
bcrypt = Bcrypt(app)

# Настройка подключения к PostgreSQL
DB_CONFIG = {
    "host": "localhost",
    "database": "myapp_db", 
    "user": "postgres",
    "password": "ВАШ_ПАРОЛЬ" # !!! ЗАМЕНИТЕ ВАШ ПАРОЛЬ !!!
}

# Разрешенные таблицы для маршрута /data/load
ALLOWED_TABLES = ['clients', 'tours', 'contracts', 'users'] 
# Ваше приложение использует базу данных 'Travel_agency', 
# но в настройках мы используем 'myapp_db'. 
# Для работы сервера убедитесь, что 'myapp_db' существует и имеет нужные таблицы.

# =========================================================================
# 2. ФУНКЦИИ БАЗЫ ДАННЫХ
# =========================================================================

def get_db_connection():
    """Возвращает соединение с базой данных, используя RealDictCursor для получения словарей."""
    conn = psycopg2.connect(**DB_CONFIG)
    return conn

# =========================================================================
# 3. АУТЕНТИФИКАЦИЯ И ТОКЕНЫ
# =========================================================================

def token_required(f):
    """Декоратор для проверки JWT токена."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            kwargs['current_user_data'] = data 
        except Exception as e:
            return jsonify({'message': f'Token is invalid: {str(e)}'}), 401

        return f(*args, **kwargs)

    return decorated

@app.route('/register', methods=['POST'])
def register():
    """Обрабатывает регистрацию нового пользователя."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Новый пользователь получает роль 'user' по умолчанию
        cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'user')",
                    (username, password_hash))
        
        conn.commit()
        cur.close()
        
        return jsonify({"message": f"User {username} registered successfully. You can now log in."}), 201

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"message": "Username already taken"}), 409
        
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        if conn: conn.close()


@app.route('/login', methods=['POST'])
def login():
    """Обрабатывает вход пользователя и возвращает JWT токен и роль."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400
        
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT id, password_hash, role FROM users WHERE username = %s", (username,))
        user_record = cur.fetchone()
        cur.close()
        conn.close()

        if user_record is None:
            return jsonify({"message": "Invalid credentials"}), 401

        user_id, stored_hash, user_role = user_record
        
        if bcrypt.check_password_hash(stored_hash, password):
            token_payload = {
                'user_id': user_id,
                'role': user_role,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
                'iat': datetime.datetime.utcnow()
            }
            token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
                "message": "Login successful",
                "token": token,
                "role": user_role
            }), 200
        else:
            return jsonify({"message": "Invalid credentials"}), 401

    except Exception as e:
        if conn: conn.close()
        return jsonify({"message": f"Server error: {str(e)}"}), 500

# =========================================================================
# 4. МАРШРУТЫ ДЛЯ ДАННЫХ (CRUD)
# =========================================================================

# Маршрут для загрузки данных из таблицы, используемый BaseForm.LoadData
@app.route('/data/load/<string:table_name>', methods=['GET'])
@token_required
def load_data(table_name, current_user_data):
    """Загружает все данные из указанной таблицы."""
    if table_name not in ALLOWED_TABLES:
        return jsonify({"message": f"Table '{table_name}' access denied or does not exist."}), 403

    conn = None
    try:
        # Используем RealDictCursor для получения данных в виде списка словарей (JSON)
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=RealDictCursor) 
        
        query = f"SELECT * FROM {table_name} ORDER BY 1"
        cur.execute(query)
        records = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return jsonify(records), 200

    except Exception as e:
        if conn: conn.close()
        # Если таблица существует в ALLOWED_TABLES, но отсутствует в БД, будет ошибка
        return jsonify({"message": f"Database query error: {str(e)}"}), 500

# =========================================================================
# 5. ЗАПУСК
# =========================================================================

if __name__ == '__main__':
    print("Running Flask app on http://127.0.0.1:5000/")
    app.run(debug=True, port=5000)
