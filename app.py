from flask import Flask, request, jsonify
import psycopg2
from flask_bcrypt import Bcrypt
import jwt # Для создания JWT токенов
import datetime
import os

# =========================================================================
# 1. КОНФИГУРАЦИЯ
# =========================================================================

app = Flask(__name__)

# Установка секретного ключа для подписи JWT токенов
# В продакшене лучше использовать переменную окружения
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_very_secret_key_change_me') 

bcrypt = Bcrypt(app)

# Настройка подключения к PostgreSQL
# Используем переменные окружения, если они доступны, иначе используем локальные настройки
DB_CONFIG = {
    "host": os.environ.get('DB_HOST', "localhost"),
    "database": os.environ.get('DB_NAME', "myapp_db"),
    "user": os.environ.get('DB_USER', "postgres"),
    # !!! ОБЯЗАТЕЛЬНО ЗАМЕНИТЕ ЭТОТ ПАРОЛЬ !!!
    "password": os.environ.get('DB_PASS', "ВАШ_ПАРОЛЬ") 
}


# =========================================================================
# 2. ФУНКЦИИ БАЗЫ ДАННЫХ
# =========================================================================

def get_db_connection():
    """Устанавливает и возвращает соединение с базой данных."""
    conn = psycopg2.connect(**DB_CONFIG)
    return conn

# =========================================================================
# 3. МАРШРУТЫ АУТЕНТИФИКАЦИИ
# =========================================================================

# --- Главная страница (проверка работы API) ---
@app.route('/', methods=['GET'])
def home():
    """Простой тестовый маршрут."""
    return jsonify({"message": "Python API is running and ready for authentication!"})


# --- Маршрут РЕГИСТРАЦИИ ---
@app.route('/register', methods=['POST'])
def register():
    """Обрабатывает регистрацию нового пользователя."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Проверка обязательных полей
    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    # Хешируем пароль с помощью Bcrypt
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Вставка нового пользователя
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                    (username, password_hash))
        
        conn.commit()
        cur.close()
        
        return jsonify({"message": f"User {username} registered successfully"}), 201

    except psycopg2.errors.UniqueViolation:
        # Обработка ошибки, если пользователь уже существует (UniqueViolation)
        conn.rollback()
        return jsonify({"message": "Username already taken"}), 409
        
    except Exception as e:
        # Общая ошибка БД
        if conn:
            conn.rollback()
        return jsonify({"message": f"Database error: {str(e)}"}), 500
        
    finally:
        if conn:
            conn.close()


# --- Маршрут ЛОГИНА ---
@app.route('/login', methods=['POST'])
def login():
    """Обрабатывает вход пользователя."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400
        
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Находим пользователя и его хеш пароля
        cur.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
        user_record = cur.fetchone()
        cur.close()
        conn.close()

        if user_record is None:
            # Пользователь не найден
            return jsonify({"message": "Invalid credentials"}), 401

        user_id = user_record[0]
        stored_hash = user_record[1]
        
        # Проверяем пароль с помощью Bcrypt
        if bcrypt.check_password_hash(stored_hash, password):
            # Если пароль верный, генерируем JWT токен
            token_payload = {
                'user_id': user_id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24), # Срок действия токена 24 часа
                'iat': datetime.datetime.utcnow()
            }
            token = jwt.encode(
                token_payload,
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            
            # Возвращаем токен клиенту
            return jsonify({
                "message": "Login successful",
                "token": token
            }), 200
        else:
            # Пароль неверный
            return jsonify({"message": "Invalid credentials"}), 401

    except Exception as e:
        if conn:
            conn.close()
        return jsonify({"message": f"Server error: {str(e)}"}), 500


# =========================================================================
# 4. ЗАПУСК
# =========================================================================

if __name__ == '__main__':
    # Убедитесь, что вы запустили: source venv/bin/activate
    # Flask запускается на 5000 порту
    print("Running Flask app on http://127.0.0.1:5000/")
    app.run(debug=True)