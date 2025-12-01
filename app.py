from flask import Flask, request, jsonify
import psycopg2
from psycopg2.extras import RealDictCursor
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my_secret_key_123'  # В продакшене замените на сложный ключ
bcrypt = Bcrypt(app)

# Настройки подключения к БД
DB_CONFIG = {
    "host": "localhost",
    "database": "Travel_agency",  # Ваша БД
    "user": "postgres",
    "password": "0000"            # Ваш пароль
}

# --- Вспомогательные функции ---

def get_db_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        print(f"Db connection error: {e}")
        return None

def init_db():
    """Создает таблицу пользователей для приложения, если её нет"""
    conn = get_db_connection()
    if conn:
        cur = conn.cursor()
        # Создаем таблицу пользователей приложения
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(200) NOT NULL,
                role VARCHAR(20) DEFAULT 'user'
            );
        """)
        # Создаем дефолтного админа (пароль 12345)
        # Хеш сгенерирован для '12345'
        default_hash = bcrypt.generate_password_hash('12345').decode('utf-8')
        cur.execute("INSERT INTO app_users (username, password_hash, role) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING", 
                    ('admin', default_hash, 'admin'))
        conn.commit()
        cur.close()
        conn.close()

# Инициализируем БД при старте
init_db()

# --- Декоратор авторизации ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            # Ожидаем заголовок "Bearer <token>"
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            # Можно добавить проверку существования пользователя в БД
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(*args, **kwargs)
    return decorated

# --- Маршруты ---

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing data"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = get_db_connection()
    if not conn: return jsonify({"message": "DB Error"}), 500
    
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO app_users (username, password_hash, role) VALUES (%s, %s, 'user')", 
                    (username, hashed_password))
        conn.commit()
        cur.close()
        return jsonify({"message": "User created successfully"}), 201
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"message": "Username already exists"}), 409
    except Exception as e:
        return jsonify({"message": str(e)}), 500
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    if not conn: return jsonify({"message": "DB Error"}), 500

    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM app_users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user and bcrypt.check_password_hash(user['password_hash'], password):
        token = jwt.encode({
            'user': user['username'],
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({'token': token, 'role': user['role']})
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/data/load/<table_name>', methods=['GET'])
@token_required
def load_data(table_name):
    # Белый список таблиц для безопасности
    ALLOWED_TABLES = ['client', 'tour', 'booking', 'hotel', 'transport', 'country', 'city']
    
    if table_name not in ALLOWED_TABLES:
        return jsonify({'message': 'Table not allowed'}), 403

    conn = get_db_connection()
    if not conn: return jsonify({"message": "DB Error"}), 500

    try:
        # Используем RealDictCursor, чтобы получить JSON-совместимый словарь
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(f"SELECT * FROM {table_name} ORDER BY 1") # ORDER BY 1 для сортировки по ID
        rows = cur.fetchall()
        cur.close()
        return jsonify(rows) # Flask автоматически преобразует список словарей в JSON
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        conn.close()

# Заглушка для удаления (нужно реализовать в C# вызов этого API)
@app.route('/data/delete/<table_name>/<id>', methods=['DELETE'])
@token_required
def delete_data(table_name, id):
    ALLOWED_TABLES = ['client', 'tour', 'booking', 'hotel', 'transport', 'country', 'city']
    if table_name not in ALLOWED_TABLES: return jsonify({'message': 'Table not allowed'}), 403
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Внимание: SQL-инъекция возможна, если id не число. В продакшене проверять тип!
        cur.execute(f"DELETE FROM {table_name} WHERE id = %s", (id,)) 
        conn.commit()
        cur.close()
        return jsonify({'message': 'Deleted'})
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
