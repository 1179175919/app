import os

import hashlib

import functools

import re

from datetime import datetime, timedelta

from flask import Flask, request, send_file, jsonify, render_template, session, redirect, url_for, flash

from flask_sqlalchemy import SQLAlchemy

from cachetools import TTLCache

from flask_limiter import Limiter

from flask_limiter.util import get_remote_address

from werkzeug.middleware.proxy_fix import ProxyFix



# --- [ 核心环境变量对齐 ] ---

# 自动读取 .service 文件中的配置

SECRET_KEY = os.environ.get("SECRET_KEY", "RK3588_SALT_999")

REAL_MODEL_FILE = os.environ.get("REAL_MODEL_FILE", "sjzA.enc")

FLASK_SEC_KEY = os.environ.get("FLASK_SECRET_KEY", "Sjz_Matrix_2026_Pro")



app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

app.secret_key = FLASK_SEC_KEY



# 强制使用绝对路径锁定数据库位置

basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'licenses.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)



# 防御系统：IP 频率限制与缓存

failed_attempts = TTLCache(maxsize=1000, ttl=300)

banned_ips = TTLCache(maxsize=1000, ttl=900)      

sn_ip_tracker = TTLCache(maxsize=5000, ttl=3600)  

limiter = Limiter(get_remote_address, app=app, default_limits=["1000 per day"], storage_uri="memory://")



# --- [ 数据库模型 ] ---

class Device(db.Model):

    """边缘计算节点设备模型"""

    id = db.Column(db.Integer, primary_key=True)

    sn = db.Column(db.String(100), unique=True, nullable=False)

    is_active = db.Column(db.Boolean, default=True)

    expire_at = db.Column(db.DateTime, nullable=True) 

    agent_name = db.Column(db.String(50), default="Admin")

    note = db.Column(db.String(200))

    last_seen = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, default=datetime.now)



class SystemConfig(db.Model):

    """系统全局配置表（用于存储动态密码）"""

    id = db.Column(db.Integer, primary_key=True)

    key = db.Column(db.String(50), unique=True)

    value = db.Column(db.String(200))



# 初始化数据库结构及种子数据

with app.app_context():

    db.create_all()

    # 初始密码逻辑：优先检查库里有没有，没有则从环境读取或设为默认

    if not SystemConfig.query.filter_by(key='admin_pwd').first():

        db.session.add(SystemConfig(key='admin_pwd', value="160363aA."))

        db.session.add(SystemConfig(key='agent_pwd', value="agent123"))

        db.session.commit()



# 登录权限校验装饰器

def login_required(func):

    @functools.wraps(func)

    def wrapper(*args, **kwargs):

        if 'role' not in session: return redirect(url_for('login'))

        return func(*args, **kwargs)

    return wrapper



@app.route('/login', methods=['GET', 'POST'])

def login():

    """后台管理登录"""

    if request.method == 'POST':

        pwd = request.form.get('password')

        # 核心修复：从数据库动态获取密码

        admin_p = SystemConfig.query.filter_by(key='admin_pwd').first().value

        agent_p = SystemConfig.query.filter_by(key='agent_pwd').first().value

        

        if pwd == admin_p:

            session['role'] = 'admin'

            return redirect(url_for('index'))

        elif pwd == agent_p:

            session['role'] = 'agent'

            return redirect(url_for('index'))

        flash('授权密钥错误', 'danger')

    return render_template('login.html')



@app.route('/logout')

def logout():

    session.pop('role', None)

    return redirect(url_for('login'))



@app.route('/')

@login_required

def index():

    """管理看板：实时维护过期状态与心跳统计"""

    devices = Device.query.order_by(Device.created_at.desc()).all()

    now = datetime.now()

    for d in devices:

        if d.is_active and d.expire_at and now > d.expire_at:

            d.is_active = False

            d.note = "🚨 [授权已过期]"

    db.session.commit()

    

    total = len(devices)

    active = sum(1 for d in devices if d.is_active)

    online_24h = sum(1 for d in devices if d.last_seen and (now - d.last_seen) < timedelta(hours=24))

    

    # 将最新密码传回前端 UI 展示

    admin_p = SystemConfig.query.filter_by(key='admin_pwd').first().value

    agent_p = SystemConfig.query.filter_by(key='agent_pwd').first().value

    

    return render_template('index.html', devices=devices, total=total, active=active, 

                           online=online_24h, role=session.get('role'),

                           admin_pwd=admin_p, agent_pwd=agent_p)



@app.route('/api/get_model')

@limiter.limit("20 per minute") 

def get_model():

    """RK3588 板端拉取加密模型接口"""

    sn = request.args.get('sn')

    token = request.args.get('token')

    if not sn or not token: return "Err", 403

    

    # 令牌校验逻辑

    now_ts = datetime.now().strftime('%Y%m%d%H%M')

    def verify_token(ts):

        device_key = hashlib.sha256(f"{sn}{SECRET_KEY}".encode()).hexdigest()

        return hashlib.sha256(f"{sn}{device_key}{ts}".encode()).hexdigest()



    if token != verify_token(now_ts): return "Unauthorized", 403



    device = Device.query.filter_by(sn=sn).first()

    if device and device.is_active:

        device.last_seen = datetime.now()

        db.session.commit()

        model_path = os.path.join(basedir, 'secure_storage', REAL_MODEL_FILE)

        return send_file(model_path)

    return "Denied", 403



@app.route('/admin/api/<action>', methods=['POST'])

@login_required

def admin_api(action):

    """后台管理核心接口"""

    data = request.json

    role = session.get('role')

    

    if action == 'add':

        sn = data.get('sn'); duration = data.get('duration')

        if not sn or Device.query.filter_by(sn=sn).first(): return jsonify({'success': False})

        

        expire_time = None

        if duration != 'perm':

            match = re.match(r"(\d+)([hd])", duration)

            if match:

                val = int(match.group(1)); unit = match.group(2)

                expire_time = datetime.now() + (timedelta(hours=val) if unit == 'h' else timedelta(days=val))

        db.session.add(Device(sn=sn, note=data.get('note', ''), expire_at=expire_time, agent_name="Admin" if role == 'admin' else "代理"))

    

    # 核心修复：添加 settings 处理逻辑，实现密码真正写入数据库

    elif action == 'settings' and role == 'admin':

        admin_rec = SystemConfig.query.filter_by(key='admin_pwd').first()

        agent_rec = SystemConfig.query.filter_by(key='agent_pwd').first()

        if data.get('admin_pwd'): admin_rec.value = data.get('admin_pwd')

        if data.get('agent_pwd'): agent_rec.value = data.get('agent_pwd')

        

    elif action == 'toggle' and role == 'admin':

        dev = Device.query.get(data.get('id'))

        if dev: dev.is_active = not dev.is_active

        

    elif action == 'delete' and role == 'admin':

        dev = Device.query.get(data.get('id'))

        if dev: db.session.delete(dev)

    

    db.session.commit()

    return jsonify({'success': True})



if __name__ == '__main__':

    app.run(host='0.0.0.0', port=5000)
