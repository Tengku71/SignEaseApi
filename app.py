from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify, Response, g, json
from werkzeug.security import check_password_hash
# from flask_pymongo import PyMongo
from pymongo import MongoClient, DESCENDING
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import bcrypt, base64
# from utils import verify_reset_token, generate_reset_token
from flask_login import LoginManager, UserMixin
from oauthlib.oauth2 import WebApplicationClient
from google.oauth2 import id_token
from google.auth.transport import requests
# import requests
from authlib.integrations.flask_client import OAuth
import jwt
from datetime import datetime, timedelta, time
from functools import wraps
import random
from bson.binary import Binary
from bson.objectid import ObjectId
from cryptography.fernet import Fernet
from pytz import timezone
import pytz
import logging
from dotenv import load_dotenv
import os

load_dotenv()

# Flask-OAuth setup
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
now = datetime.now(pytz.timezone("Asia/Jakarta"))


client = MongoClient(
    os.getenv("MONGO_URI"),
    serverSelectionTimeoutMS=10000
)


mongo = client['MyProject']

# Flask-Mail configuration
app.config['MAIL_SERVER'] = os.environ.get("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.environ.get("MAIL_PORT", 587))
app.config['MAIL_USE_TLS'] = os.environ.get("MAIL_USE_TLS", "True") == "True"
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_DEFAULT_SENDER")

mail = Mail(app)

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

################################################################################
                            #endpoint google                                 #
################################################################################                                       

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')

@app.route('/api/login-google', methods=['POST'])
def login_google_mobile():
    try:
        data = request.get_json()
        id_token_str = data.get('idToken')
        local_tz = pytz.timezone("Asia/Jakarta")

        if not id_token_str:
            return jsonify({'success': False, 'message': 'ID Token is required'}), 400

        # Verify and decode the Google idToken.
        idinfo = id_token.verify_oauth2_token(id_token_str, requests.Request(), GOOGLE_CLIENT_ID)

        # Extract user information from the verified token.
        user_info = {
            'id': idinfo['sub'],               # Google's unique user ID.
            'email': idinfo['email'],
            'name': idinfo.get('name'),
            'picture': idinfo.get('picture'),
        }

        # Optionally, look for an existing user record or create a new one.
        existing_user = mongo.db.users.find_one({'email': user_info['email']})
        if not existing_user:
            mongo.db.users.insert_one({
                'nama': user_info['name'],
                'email': user_info['email'],
                'confirmed': False,
            })
            otp_generate(user_info['email'], user_info['name'])
            return jsonify({
                'success': True,
                'email': user_info['email'],
                'message': 'otp',
            }), 200

        if existing_user['confirmed'] == False:
            print(f"Before otp_generate, user email: {user_info['email']}")
            result = otp_generate(user_info['email'], user_info['name'])
            print(f"otp_generate returned: {result} (type: {type(result)})")
            return jsonify({
                'success': False,
                'email': user_info['email'],
                'message': 'otp',
            }), 200

        user = mongo.db.users.find_one({'email': user_info['email']})
        local_tz = pytz.timezone("Asia/Jakarta")
        login_time = datetime.now(local_tz)
        login_data = {
            'user_id': str(user['_id']),
            'email' : user['email'],
            'timestamp': login_time,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        }
        mongo.db.login_history.insert_one(login_data)
        
        # Generate your own JWT token to use for your application.
        role = 'admin' if user_info['email'] == 'admin@example.com' else 'user'
        token_jwt = generate_jwt(user_info['id'], role)
        send_login_notification(idinfo['email'], idinfo.get('name'))

        return jsonify({
            'success': True,
            'message': 'Login Google berhasil',
            'token': token_jwt,
            'user': {
                'name': user.get('nama', ''),
                'profileImage': user.get('profileImage', ''),
                'email': user.get('email', ''),
            }
        }), 200


    except ValueError:
        # Raised if the idToken fails verification.
        return jsonify({'success': False, 'message': 'Invalid ID token'}), 401
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    

################################################################################
                            #endpoint google                                 #
################################################################################                                       


# Token generation and confirmation function
serializer = URLSafeTimedSerializer(app.secret_key)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.name = user_data['name']
        self.email = user_data['email']

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({"_id": user_id})
    if user_data:
        return User(user_data)
    return None


################################################################################
                            #FUNC BASIC AUTH                                   #
################################################################################                                       


def basic_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username == 'admin' and auth.password == 'admin123'):
            return Response(
                'Could not verify your login.\n'
                'You have to login with proper credentials',
                401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'}
            )
        return f(*args, **kwargs)
    return decorated


################################################################################
                             # Bagian ADMIN                                  #
################################################################################                                       
                  

@app.route('/', methods=["GET"])
def home():
    jumlah_akun = mongo.db.users.count_documents({})

    wib = timezone('Asia/Jakarta')
    now = datetime.now(wib)

    start_of_day = datetime.combine(now.date(), time.min).replace(tzinfo=wib)
    end_of_day = datetime.combine(now.date(), time.max).replace(tzinfo=wib)

    unique_users = mongo.db.login_history.distinct(
        "user_id",  # Replace with your field name
        {
            "timestamp": {"$gte": start_of_day, "$lte": end_of_day}
        }
    )

    jumlah_login_harian = len(unique_users)

    return render_template(
        'Home/dashboard.html',
        jumlah_akun=jumlah_akun,
        login_harian=jumlah_login_harian
    )

# Bagian LeaderBoard
@app.route('/leaderboard', methods=['GET'])
def leaderboard():
    users = list(mongo.db.users.find({"points": {"$exists": True}}).sort("points", -1))

    user_id = request.args.get("user_id")
    nama = request.args.get("nama")
    points = request.args.get("points")

    error = None
    if user_id is None:
        error = "user_id tidak ditemukan"
    elif points is None:
        error = "points tidak ditemukan"

    return render_template('leaderboard/data.html', users=users, error=error)


# Reset Point (admin)
@app.route('/reset_point', methods=['POST'])
def reset_point():
    user_id = request.form.get('user_id')  # Harus dari POST body, bukan query string

    if not user_id:
        return jsonify({"error": "user_id tidak diberikan"}), 400

    # Jika user_id adalah MongoDB ObjectId
    from bson import ObjectId
    try:
        result = mongo.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"points": 0}}
        )
    except:
        return jsonify({"error": "user_id tidak valid"}), 400

    if result.matched_count == 0:
        return jsonify({"error": "User tidak ditemukan"}), 404

    return redirect(url_for('leaderboard', user_id=user_id))


@app.route('/logout')
def logout():
    session.clear()
    flash('Logout berhasil!', 'success')
    return redirect(url_for('home'))

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    error = request.args.get('error')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = mongo.db.Admin.find_one({'username': username})

        if user and check_password_hash(user.get('password', ''), password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return redirect(url_for('add_user', error='username atau password salah'))

    return render_template('Login/sign-in.html', error=error)


@app.route('/login_history', methods=['GET'])
def admin_login_history():
    if 'username' not in session:
        flash('Anda harus login sebagai admin untuk mengakses halaman ini!', 'danger')
        return redirect(url_for('add_user', error='Silakan login terlebih dahulu'))

    try:
        local_tz = pytz.timezone("Asia/Jakarta")
        history = mongo.db.login_history.find().sort('timestamp', -1)
        history_list = []

        for entry in history:
            timestamp = entry.get('timestamp')
            if timestamp:
                timestamp_wib = timestamp.astimezone(local_tz).strftime('%Y-%m-%d %H:%M:%S WIB')
            else:
                timestamp_wib = 'Tidak tersedia'

            history_list.append({
                '_id': str(entry.get('_id')),
                'user_id': entry.get('user_id', 'N/A'),
                'email': entry.get('email', 'N/A'),
                'timestamp': timestamp_wib,
                'ip_address': entry.get('ip_address', 'N/A'),
                'user_agent': entry.get('user_agent', 'N/A')
            })

        logging.debug(f"Histori login yang diambil: {history_list}")
        return render_template('leaderboard/tables.html', history=history_list, title='Histori Login Pengguna')

    except Exception as e:
        logging.error(f"Error di admin_login_history: {str(e)}")
        flash(f'Terjadi kesalahan: {str(e)}', 'danger')
        return render_template('leaderboard/tables.html', history=[], title='Histori Login Pengguna')


@app.route('/profile')
def profile():
    username = session.get('username')  # Ambil user_id dari session
    if not username:
        return redirect('add_user')

    users = mongo.db.Admin.find_one({'username': username})
    if not users:
        return "User not found", 404
    return render_template('Profile/profile.html', users=users)

@app.route('/admin/dashboard')
@basic_auth_required
def admin_dashboard():
    return jsonify({'message': 'Selamat datang, Admin!'})


################################################################################
                                       #ADMIN                                  #
################################################################################                                       
                  

################################################################################
                            #func forgot pass                                  #
################################################################################                                       

# Request reset password
@app.route('/request-reset', methods=['POST'])
def request_reset():
    email = request.form.get('email')

    if not email:
        return jsonify({'status': 'fail', 'message': 'Email tidak boleh kosong'}), 400

    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'status': 'fail', 'message': 'Email tidak terdaftar'}), 404

    token = generate_reset_token(email)
    reset_url = f'https://signease.tengkudimas.my.id/reset-password/{token}'

    try:
        msg = Message("Reset Password Anda",
                      sender="ezzdarkrap2@gmail.com",
                      recipients=[email])
        msg.body = f"Klik tautan berikut untuk mereset password Anda: {reset_url}"
        mail.send(msg)
    except Exception as e:
        return jsonify({'status': 'fail', 'message': 'Gagal mengirim email'}), 500

    return jsonify({'status': 'success', 'message': 'Tautan reset password telah dikirim ke email'}), 200

# Reset password route
@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    email = verify_reset_token(token)

    if email is None:
        return jsonify({'status': 'fail', 'message': 'Token tidak valid atau kadaluarsa'}), 400

    password = request.form.get('Password')
    if not password:
        return jsonify({'status': 'fail', 'message': 'Password tidak boleh kosong'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'status': 'fail', 'message': 'Pengguna tidak ditemukan'}), 404

    mongo.db.users.update_one({'email': email}, {'$set': {'password': hashed_password}})

    return jsonify({'status': 'success', 'message': 'Password berhasil diubah'}), 200


# Token generation and confirmation function
serializer = URLSafeTimedSerializer(app.secret_key)

def generate_reset_token(email, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email)

# Fungsi untuk memverifikasi token reset password
def verify_reset_token(token, expiration=3600):
    """
    Memverifikasi apakah token reset password masih valid dan belum kadaluarsa.
    """
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        # Memuat email dari token dan memeriksa apakah masih dalam masa berlaku
        email = serializer.loads(token, max_age=expiration)
    except SignatureExpired:
        # Jika token sudah kadaluarsa
        return None
    except Exception:
        # Jika token tidak valid
        return None
    return email

def generate_confirmation_token(email):
    return serializer.dumps(email, salt='email-confirmation-salt')

def confirm_token(token, expiration=3600):  # Default: 1 hour
    try:
        email = serializer.loads(token, salt='email-confirmation-salt', max_age=expiration)
    except Exception as e:
        return False
    return email

################################################################################
                            #func forgot pass                                  #
################################################################################                                       


# # User class for Flask-Login
# class User(UserMixin):
#     def __init__(self, user_data):
#         self.id = str(user_data['_id'])
#         self.name = user_data['name']
#         self.email = user_data['email']

# # User loader for Flask-Login
# @login_manager.user_loader
# def load_user(user_id):
#     user_data = mongo.db.users.find_one({"_id": user_id})
#     if user_data:
#         return User(user_data)
#     return None





################################################################################
                                       #JWT                                    #
################################################################################   
                                                                     
# func JWT
FERNET_KEY = Fernet.generate_key() 
cipher = Fernet(FERNET_KEY)

# func JWT
def generate_jwt(user_id, role):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': (datetime.now() + timedelta(hours=1)).timestamp(),
        'iat': datetime.now().timestamp()
    }
    # Encrypt the payload
    encrypted_payload = cipher.encrypt(json.dumps(payload).encode())
    token = jwt.encode({'data': encrypted_payload.decode()}, app.secret_key, algorithm='HS256')
    return token

def decode_jwt(token):
    try:
        decoded = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        decrypted = cipher.decrypt(decoded['data'].encode())
        payload = json.loads(decrypted)
        # validate expiry manually
        if datetime.now().timestamp() > payload['exp']:
            return None
        return payload
    except Exception:
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        if token.startswith("Bearer "):
            token = token[len("Bearer "):]

        payload = decode_jwt(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401

        g.user_id = payload['user_id']
        g.role = payload['role']
        return f(*args, **kwargs)
    return decorated
    
@app.route('/verify-token', methods=['GET'])
@token_required
def verify_token():
    return jsonify({
        'message': 'Token is valid',
    }), 200

################################################################################
                                       #JWT                                    #
################################################################################   

################################################################################
                                       #OTP                                    #
################################################################################ 


def send_login_notification(email, nama):
    if not email:
        print("[ERROR] Email is missing in send_login_notification.")
        return

    if not nama:
        nama = "Pengguna"

    # Waktu lokal
    local_tz = pytz.timezone("Asia/Jakarta")
    now = datetime.now(local_tz).strftime("%d-%m-%Y %H:%M:%S")

    # Reset URL (for safety link if user didn't login)
    token = generate_reset_token(email)
    reset_url = f'https://signease.tengkudimas.my.id/reset-password/{token}'

    subject = "Notifikasi Login - Akun Anda"
    msg = Message(subject=subject, recipients=[email])
    msg.body = f"""
    Halo {nama},

    Kami mendeteksi login ke akun Anda pada:

    📅 Tanggal & Waktu: {now} (WIB)

    Jika ini adalah Anda, abaikan email ini.

    Jika **bukan** Anda, segera amankan akun Anda dengan mengganti password di tautan ini:
    {reset_url}

    Terima kasih,
    Tim Keamanan SignEase
    """

    try:
        mail.send(msg)
        print("Login notification email sent successfully.")
    except Exception as e:
        print(f"Failed to send login notification email: {e}")

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400

        user = mongo.db.users.find_one({'email': email})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        if user.get('confirmed', False):
            return jsonify({'success': False, 'message': 'Account already verified'}), 400

        # Send OTP
        otp_generate(email, user.get('nama'))

        return jsonify({'success': True, 'message': 'OTP resent'}), 200

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


def otp_generate(email, nama):
    otp_code = str(random.randint(1000, 9999))
    local_tz = pytz.timezone("Asia/Jakarta")
    now = datetime.now(local_tz)
    expires_at = (now + timedelta(minutes=5)).replace(tzinfo=None)  # naive but still Jakarta local time


    # 🔄 Delete any existing OTPs for this email
    mongo.db.otps.delete_many({'email': email})

    # 🆕 Create a new OTP record
    otp_data = {
        'email': email,
        'otp': otp_code,
        'expires_at': expires_at
    }
    mongo.db.otps.insert_one(otp_data)

    # ✉️ Send OTP email
    subject = "Verifikasi Akun - Kode OTP"
    msg = Message(subject, recipients=[email])
    msg.body = f"""
    Halo {nama},

    Kode OTP Anda untuk verifikasi akun adalah: {otp_code}

    Kode ini berlaku selama 5 menit. Jangan berikan kepada siapa pun.

    Jika Anda tidak merasa mendaftar, abaikan email ini.
    """

    try:
        mail.send(msg)
        print("OTP email sent successfully.")
    except Exception as e:
        print(f"Failed to send OTP email: {e}")

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    local_tz = pytz.timezone("Asia/Jakarta")
    data = request.get_json()

    email = data.get('email')
    otp_input = data.get('otp')
    print(data)

    # 🔍 Fetch user and OTP record
    user = mongo.db.users.find_one({'email': email})
    otp_record = mongo.db.otps.find_one({'email': email})

    if not otp_record:
        return jsonify({'status': 'error', 'message': 'OTP tidak ditemukan'}), 404

    if otp_record['otp'] != otp_input:
        return jsonify({'status': 'error', 'message': 'OTP salah'}), 400

    # 🕒 Handle time correctly
    now = datetime.now(local_tz)
    expires_at = otp_record['expires_at']

    # Ensure expires_at is timezone-aware
    if expires_at.tzinfo is None:
        expires_at = local_tz.localize(expires_at)

    if now > expires_at:
        return jsonify({'status': 'error', 'message': 'OTP sudah kedaluwarsa'}), 400

    # ✅ OTP is valid
    mongo.db.users.update_one({'email': email}, {'$set': {'confirmed': True}})
    mongo.db.otps.delete_many({'email': email})

    token_jwt = generate_jwt(str(user['_id']), "user")

    return jsonify({
        'status': "success",
        'message': 'Verifikasi berhasil',
        'token': token_jwt,
    }), 200



    # return jsonify({'status': 'success', 'message': 'Verifikasi berhasil'})




################################################################################
                        #Endpoint API USER                                    #
################################################################################ 

@app.route('/get_user', methods=['GET'])
@token_required
def get_user():
    # Pastikan g.user_id adalah string yang bisa dikonversi ke ObjectId
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(g.user_id)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        
        'email': user.get('email', '')
    })

@app.route('/logout_u')
@token_required
def logout_user():
    return jsonify({"message": "berhasil logout!"}), 200

@app.route('/login_u', methods=['POST'])
def user_login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']  # plain text password from client

        user = mongo.db.users.find_one({'email': email})
        if not user:
            return jsonify({'error': 'Email atau password salah'}), 401

        stored_password = user.get('password')
        if not stored_password:
            return jsonify({'error': 'Password tidak ditemukan'}), 400

        # stored_password may be bytes or string, convert to bytes if string
        if isinstance(stored_password, str):
            stored_password = stored_password.encode('utf-8')

        password_bytes = password.encode('utf-8')

        # bcrypt password check
        if not bcrypt.checkpw(password_bytes, stored_password):
            return jsonify({'error': 'Email atau password salah'}), 401

        if not user.get('confirmed', False):
            result = otp_generate(email, user.get('nama', 'User'))
            return jsonify({'success': False, 'email': email, 'message': 'otp'}), 200

        token = generate_jwt(str(user['_id']), 'user')

        send_login_notification(email, user["nama"])
        local_tz = pytz.timezone("Asia/Jakarta")

        login_time = datetime.now(local_tz)
        login_data = {
            'user_id': str(user['_id']),
            'email': email,
            'timestamp': login_time,
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        }

        mongo.db.login_history.insert_one(login_data)

        return jsonify({
            'message': 'Login berhasil',
            'token': token,
            'user': {
                'name': user.get('nama', ''),
                'profileImage': user.get('profileImage', ''),
                'level': user.get('level', 0),
                'history': user.get('history', []),
                'leaderboardScore': user.get('leaderboardScore', 0),
                'email': user.get('email', ''),
                'kelas': user.get('kelas', ''),
                'points': user.get('points', 0),
            }
        }), 200


    except Exception as e:
        # traceback.print_exc()
        return jsonify({'error': f'Terjadi kesalahan: {str(e)}'}), 500


@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        nama = data['nama']
        email = data['email']
        jeniskelamin = data['jeniskelamin']
        tanggal_lahir = data['tanggal_lahir']
        alamat = data['alamat']
        password = data['password'].encode('utf-8')
        confirmpassword = data['confirmpassword'].encode('utf-8')

        # Validasi password
        if password != confirmpassword:
            flash('Password dan konfirmasi password tidak cocok', 'danger')
            return jsonify({"message":'Password dan konfirmasi password tidak cocok'})

        if len(password) < 6:
            flash('Password harus lebih dari 6 karakter', 'danger')
            return jsonify({"message":'Password harus lebih dari 6 karakter'})

        if mongo.db.users.find_one({'email': email}):
            flash('Email sudah terdaftar', 'danger')
            return jsonify({"message":'Email sudah terdaftar'})

        # Hash password
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        # Simpan user
        user_data = {
            'nama': nama,
            'email': email,
            'password': hashed_password,
            'jeniskelamin': jeniskelamin,
            'tanggal_lahir': tanggal_lahir,
            'alamat': alamat,
            'confirmed': False
        }
        mongo.db.users.insert_one(user_data)

        otp_generate(email, nama)

    return jsonify({'success': True, 'email': email, 'message': 'otp'}), 201

@app.route('/user', methods=['GET'])
@token_required
def get_user_by_token():
    try:
        user_id = g.user_id
        
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        
        if user:
            user['_id'] = str(user['_id'])
            user.pop('password', None)
            return jsonify({'status': 'success', 'user': user})
        else:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Invalid ID format or server error: {str(e)}'}), 400

@app.route('/edit_user', methods=['PUT'])
@token_required
def edit_user():
    try:
        data = request.get_json()
        
        user_id = g.user_id
        
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})

        if not user:
            return jsonify({'error': 'User tidak ditemukan'}), 404

        update_data = {}
        if 'nama' in data:
            update_data['nama'] = data['nama']
        if 'jeniskelamin' in data:
            update_data['jeniskelamin'] = data['jeniskelamin']
        if 'tanggal_lahir' in data:
            update_data['tanggal_lahir'] = data['tanggal_lahir']
        if 'alamat' in data:
            update_data['alamat'] = data['alamat']
        if 'password' in data and 'confirmpassword' in data:
            password = data['password'].encode('utf-8')
            confirmpassword = data['confirmpassword'].encode('utf-8')
            if password != confirmpassword:
                return jsonify({'error': 'Password dan konfirmasi password tidak cocok'}), 400
            if len(password) < 6:
                return jsonify({'error': 'Password harus lebih dari 6 karakter'}), 400
            update_data['password'] = bcrypt.hashpw(password, bcrypt.gensalt())

        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})
        return jsonify({'message': 'User berhasil diperbarui'})

    except Exception as e:
        return jsonify({'error': f'Kesalahan server: {str(e)}'}), 400


@app.route('/delete_user', methods=['DELETE'])
@token_required
def delete_user():
    try:
        user_id = g.user_id
        
        result = mongo.db.users.delete_one({'_id': ObjectId(user_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'User tidak ditemukan'}), 404
        return jsonify({'message': 'User berhasil dihapus'})
    except Exception as e:
        return jsonify({'error': f'Kesalahan server: {str(e)}'}), 400

@app.route('/login_history_user', methods=['GET'])
@token_required
def get_login_history():
    try:
        if not user_id:
            return jsonify({'error': 'Parameter user_id wajib diisi'}), 400        
        user = mongo.db.users.find_one({'_id': ObjectId(g.user_id)})
        if not user:
            return jsonify({'error': 'User tidak ditemukan'}), 404
            
        history_cursor = mongo.db.login_history.find({'user_id': user_id}).sort('timestamp', -1)
        
        history = []
        for entry in history_cursor:
            history.append({
                'email': entry.get('email'),
                'timestamp': entry.get('timestamp').strftime('%Y-%m-%d %H:%M:%S'),
                'ip_address': entry.get('ip_address'),
                'user_agent': entry.get('user_agent')
            })

        return jsonify({'login_history': history}), 200

    except Exception as e:
        return jsonify({'error': f'Terjadi kesalahan: {str(e)}'}), 500

