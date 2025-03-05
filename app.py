from flask import Flask, request, jsonify, make_response, send_file, redirect, render_template, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import random
import string
from datetime import datetime, timedelta
from captcha.image import ImageCaptcha
import io
import os

app = Flask(__name__, static_url_path='', static_folder='pictures')
app.config['SECRET_KEY'] = 'your-secret-key'

# 使用绝对路径配置数据库
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 确保instance文件夹存在
os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)

# 确保在创建所有路由之前初始化数据库
with app.app_context():
    db.create_all()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_password_change = db.Column(db.DateTime)
    security_question1 = db.Column(db.String(10))
    security_answer1 = db.Column(db.String(100))
    security_question2 = db.Column(db.String(10))
    security_answer2 = db.Column(db.String(100))

# 存储验证码的字典
captcha_store = {}
email_code_store = {}
sms_code_store = {}

def verify_captcha(captcha_input):
    session_id = request.cookies.get('session_id')
    stored_captcha = captcha_store.get(session_id)
    
    if not stored_captcha:
        return False
        
    # 验证成功后删除存储的验证码
    result = stored_captcha.lower() == captcha_input.lower()
    if result:
        del captcha_store[session_id]
    return result

def verify_email_code(email, code):
    stored_code = email_code_store.get(email)
    if not stored_code:
        return False
    return stored_code == code

@app.route('/')
def home():
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/api/captcha')
def generate_captcha():
    image = ImageCaptcha()
    # 生成4位随机验证码
    captcha_text = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
    session_id = request.cookies.get('session_id', str(random.randint(1000, 9999)))
    captcha_store[session_id] = captcha_text
    print(f"Generated captcha: {captcha_text} for session: {session_id}")  # 调试信息
    
    # 生成图片
    image_data = image.generate(captcha_text)
    response = make_response(send_file(io.BytesIO(image_data.read()), mimetype='image/png'))
    response.set_cookie('session_id', session_id)
    return response

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': '用户名已存在'}), 400
        
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': '邮箱已被使用'}), 400
        
    user = User(
        username=data['username'],
        email=data['email'],
        password_hash=generate_password_hash(data['password']),
        last_password_change=datetime.now()
    )
    
    try:
        db.session.add(user)
        db.session.commit()
        # 将用户名存储在session中，用于设置安全问题
        session['registered_username'] = data['username']
        return jsonify({'message': '注册成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': '注册失败，请稍后重试'}), 500

@app.route('/api/verify-password', methods=['POST'])
def verify_password():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    # 检查账户是否锁定
    if user and user.locked_until and user.locked_until > datetime.now():
        return jsonify({'error': '账户已锁定，请稍后再试'}), 403
    
    # 验证图形验证码
    if not verify_captcha(data['captcha']):
        return jsonify({'error': '图形验证码错误'}), 400

    # 验证用户是否存在
    if not user:
        return jsonify({'error': '用户名不存在'}), 401

    # 验证密码
    if not check_password_hash(user.password_hash, data['password']):
        user.login_attempts += 1
        if user.login_attempts >= 5:
            user.locked_until = datetime.now() + timedelta(minutes=30)
        db.session.commit()
        return jsonify({'error': '密码错误'}), 401
    
    # 将验证状态存储在session中
    session['password_verified'] = True
    session['verified_username'] = data['username']
    
    return jsonify({'message': '密码验证成功'})

@app.route('/api/verify-sms', methods=['POST'])
def verify_sms():
    data = request.get_json()
    username = data['username']
    
    # 检查是否已通过密码验证
    if not session.get('password_verified') or session.get('verified_username') != username:
        return jsonify({'error': '请先完成密码验证'}), 401
    
    # 验证图形验证码
    if not verify_captcha(data['captcha']):
        return jsonify({'error': '图形验证码错误'}), 400
    
    # 验证短信验证码
    stored_code = sms_code_store.get(username)
    if not stored_code or stored_code != data['smsCode']:
        return jsonify({'error': '短信验证码错误'}), 400
    
    # 将验证状态存储在session中
    session['sms_verified'] = True
    
    return jsonify({'message': '短信验证成功'})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    
    # 检查是否完成了所有验证步骤
    if not session.get('password_verified') or \
       not session.get('sms_verified') or \
       not session.get('security_verified') or \
       session.get('verified_username') != username:
        return jsonify({'error': '请完成所有验证步骤'}), 401
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    # 清除所有验证状态和验证码
    session.pop('password_verified', None)
    session.pop('sms_verified', None)
    session.pop('security_verified', None)
    session.pop('verified_username', None)
    if username in sms_code_store:
        del sms_code_store[username]
    
    # 登录成功，清除失败计数
    user.login_attempts = 0
    db.session.commit()
    
    # 生成JWT令牌
    token = generate_token(user.id)
    return jsonify({'token': token})

def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256') 

@app.route('/api/send-email-code', methods=['POST'])
def send_email_code():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({'error': '该邮箱未注册'}), 404
        
    # 生成6位数字验证码
    code = ''.join(random.choices(string.digits, k=6))
    email_code_store[email] = code
    
    # TODO: 实际发送邮件的代码
    # 这里为了演示，直接返回验证码
    return jsonify({
        'message': '验证码已发送',
        'code': code  # 实际生产环境中不应返回验证码
    })

@app.route('/api/verify-email', methods=['POST'])
def verify_email():
    email = request.json.get('email')
    code = request.json.get('code')
    
    stored_code = email_code_store.get(email)
    if not stored_code or stored_code != code:
        return jsonify({'error': '验证码错误'}), 400
        
    return jsonify({'message': '验证成功'})

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    email = request.json.get('email')
    new_password = request.json.get('password')
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': '用户不存在'}), 404
        
    # 更新密码
    user.password_hash = generate_password_hash(new_password)
    user.last_password_change = datetime.now()
    db.session.commit()
    
    return jsonify({'message': '密码重置成功'})

@app.route('/api/send-sms-code', methods=['POST'])
def send_sms_code():
    username = request.json.get('username')
    user = User.query.filter_by(username=username).first()
    
    if not user:
        return jsonify({'error': '用户不存在'}), 404
        
    # 生成6位数字验证码
    code = ''.join(random.choices(string.digits, k=6))
    sms_code_store[username] = code
    
    # 在实际应用中，这里应该调用短信服务发送验证码
    # 这里为了演示，直接返回验证码
    return jsonify({
        'message': '验证码已发送',
        'code': code  # 实际生产环境中不应返回验证码
    })

@app.route('/welcome')
def welcome_page():
    return render_template('welcome.html')

@app.route('/api/user-info')
def get_user_info():
    # 从请求头获取token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': '未授权访问'}), 401
    
    token = auth_header.split(' ')[1]
    try:
        # 验证token
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(payload['user_id'])
        if not user:
            return jsonify({'error': '用户不存在'}), 404
            
        return jsonify({
            'username': user.username,
            'email': user.email
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'token已过期'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': '无效的token'}), 401

@app.route('/reset-password')
def reset_password_page():
    return render_template('reset_password.html')

@app.route('/security-questions')
def security_questions_page():
    # 检查是否有注册用户的session
    if not session.get('registered_username'):
        return redirect(url_for('login_page'))
    return render_template('security_questions.html')

@app.route('/api/set-security-questions', methods=['POST'])
def set_security_questions():
    data = request.get_json()
    
    # 从session中获取刚注册的用户名
    username = session.get('registered_username')
    if not username:
        return jsonify({'error': '会话已过期，请重新注册'}), 401
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    try:
        # 保存安全问题和答案
        user.security_question1 = data['question1']
        user.security_answer1 = data['answer1']
        user.security_question2 = data['question2']
        user.security_answer2 = data['answer2']
        
        db.session.commit()
        # 清除session中的临时数据
        session.pop('registered_username', None)
        return jsonify({'message': '安全问题设置成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': '设置失败，请稍后重试'}), 500

@app.route('/api/verify-security-question', methods=['POST'])
def verify_security_question():
    data = request.get_json()
    username = data.get('username')
    question_id = data.get('questionId')  # 1 或 2
    answer = data.get('answer')
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    # 验证答案
    if question_id == '1':
        if not user.security_answer1:
            return jsonify({'error': '未设置安全问题'}), 400
        stored_answer = user.security_answer1
    else:
        if not user.security_answer2:
            return jsonify({'error': '未设置安全问题'}), 400
        stored_answer = user.security_answer2
    
    if answer.strip().lower() != stored_answer.strip().lower():
        return jsonify({'error': '答案错误'}), 400
    
    # 验证成功，将状态存储在session中
    session['security_verified'] = True
    return jsonify({'message': '验证成功'})

# 定义安全问题列表
SECURITY_QUESTIONS = {
    '1': '您的出生地是？',
    '2': '您的母亲的名字是？',
    '3': '您的第一所学校是？',
    '4': '您最喜欢的颜色是？',
    '5': '您的宠物的名字是？'
}

@app.route('/api/get-security-questions', methods=['POST'])
def get_security_questions():
    data = request.get_json()
    username = data.get('username')
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    # 获取用户设置的两个问题
    question1 = SECURITY_QUESTIONS[user.security_question1]
    question2 = SECURITY_QUESTIONS[user.security_question2]
    
    return jsonify({
        'question1': question1,
        'question2': question2
    })

@app.route('/api/verify-security-questions', methods=['POST'])
def verify_security_questions():
    data = request.get_json()
    username = data.get('username')
    answers = data.get('answers')
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    # 验证两个答案
    if not user.security_answer1 or not user.security_answer2:
        return jsonify({'error': '未设置安全问题'}), 400
    
    answer1_correct = answers['answer1'].strip().lower() == user.security_answer1.strip().lower()
    answer2_correct = answers['answer2'].strip().lower() == user.security_answer2.strip().lower()
    
    if not answer1_correct or not answer2_correct:
        return jsonify({'error': '安全问题答案错误'}), 400
    
    # 验证成功，将状态存储在session中
    session['security_verified'] = True
    return jsonify({'message': '验证成功'})

if __name__ == '__main__':
    with app.app_context():
        # 创建所有数据库表
        db.drop_all()  # 删除所有现有表
        db.create_all()  # 创建新表
    app.run(debug=True)