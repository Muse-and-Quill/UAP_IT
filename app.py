import os
from flask import Flask, app, render_template, request, redirect, url_for, flash, make_response, current_app
from flask_mail import Mail, Message
from models import db, Employee
from dotenv import load_dotenv
from passlib.hash import pbkdf2_sha256
import jwt
import datetime
import random
import string

load_dotenv()

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    # config from environment
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
    app.config['JWT_SECRET'] = os.getenv('JWT_SECRET', 'jwt-dev-secret')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///employees.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # mail
# replace your mail config code with this block (in create_app())
    app.config.update(
        MAIL_SERVER=os.getenv('MAIL_SERVER'),
        MAIL_PORT=int(os.getenv('MAIL_PORT', 465)),
        MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
        MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
        MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER', os.getenv('MAIL_USERNAME')),
        MAIL_USE_TLS=(os.getenv('MAIL_USE_TLS', 'False') == 'True'),
        MAIL_USE_SSL=(os.getenv('MAIL_USE_SSL', 'False') == 'True'),
    )

    mail = Mail(app)

    

    # create database tables if not present
    with app.app_context():
        db.create_all()

    def gen_otp():
        return str(random.randint(100000, 999999))

    @app.route('/')
    def index():
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            emp_id = request.form.get('employee_id', '').strip()
            password = request.form.get('password', '')

            if not emp_id or not password:
                flash('Enter both Employee ID and password', 'danger')
                return redirect(url_for('login'))

            user = Employee.query.filter_by(employee_id=emp_id).first()
            if not user:
                flash('Invalid Employee ID or password', 'danger')
                return redirect(url_for('login'))

            if not pbkdf2_sha256.verify(password, user.password_hash):
                flash('Invalid Employee ID or password', 'danger')
                return redirect(url_for('login'))

            # create OTP and sign as short-lived JWT
            otp = gen_otp()
            payload = {
                'email': user.email,
                'otp': otp,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=7)
            }
            token = jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')
            # send OTP email
            try:
                msg = Message('Your Login OTP', recipients=[user.email])
                msg.body = f'Hello {user.name},\n\nYour OTP to complete login: {otp}\nThis code expires in 7 minutes.\n\nIf you did not request this, ignore.'
                mail.send(msg)
            except Exception as e:
    # detailed logging for deploy logs
                current_app.logger.exception('Failed to send OTP email — full exception follows')
                current_app.logger.error('Mail config: server=%s port=%s tls=%s ssl=%s user=%s',
                                        app.config.get('MAIL_SERVER'),
                                        app.config.get('MAIL_PORT'),
                                        app.config.get('MAIL_USE_TLS'),
                                        app.config.get('MAIL_USE_SSL'),
                                        app.config.get('MAIL_USERNAME'))
                flash('Failed to send OTP. Contact admin.', 'danger')
                return redirect(url_for('login'))


            resp = make_response(redirect(url_for('verify_otp')))
            # store otp token in an httpOnly cookie (short lived)
            resp.set_cookie('otp_token', token, httponly=True, samesite='Lax')
            return resp

        return render_template('login.html')

    @app.route('/verify-otp', methods=['GET', 'POST'])
    def verify_otp():
        if request.method == 'POST':
            entered = request.form.get('otp', '').strip()
            token = request.cookies.get('otp_token')
            if not token:
                flash('OTP session expired. Please login again.', 'danger')
                return redirect(url_for('login'))
            try:
                data = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                flash('OTP expired. Please login again.', 'danger')
                return redirect(url_for('login'))
            except Exception:
                flash('OTP validation failed. Please login again.', 'danger')
                return redirect(url_for('login'))

            if entered == data.get('otp'):
                # issue auth token (2-hour expiry)
                auth_payload = {
                    'email': data.get('email'),
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
                }
                auth_token = jwt.encode(auth_payload, app.config['JWT_SECRET'], algorithm='HS256')
                resp = make_response(redirect(url_for('dashboard')))
                resp.set_cookie('auth_token', auth_token, httponly=True, samesite='Lax')
                # clear otp_token
                resp.set_cookie('otp_token', '', expires=0)
                return resp
            else:
                flash('Invalid OTP', 'danger')

        return render_template('verify_otp.html')

    def auth_required(fn):
        from functools import wraps
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = request.cookies.get('auth_token')
            if not token:
                return redirect(url_for('login'))
            try:
                jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
            except Exception:
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return wrapper

    @app.route('/dashboard')
    @auth_required
    def dashboard():
        return render_template('dashboard.html')

    # forgot password - step1: request OTP by providing employee_id & email
    @app.route('/forgot', methods=['GET', 'POST'])
    def forgot():
        if request.method == 'POST':
            emp_id = request.form.get('employee_id', '').strip()
            email = request.form.get('email', '').strip()
            user = Employee.query.filter_by(employee_id=emp_id, email=email).first()
            if not user:
                flash('Employee ID and Email do not match', 'danger')
                return redirect(url_for('forgot'))

            otp = gen_otp()
            payload = {'email': user.email, 'otp': otp, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}
            token = jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')
            try:
                msg = Message('Password Reset OTP', recipients=[user.email])
                msg.body = f'Hello {user.name},\n\nYour password reset OTP: {otp}\nExpires in 10 minutes.'
                mail.send(msg)
            except Exception:
                current_app.logger.exception('Failed to send reset OTP')

            resp = make_response(redirect(url_for('reset_verify')))
            resp.set_cookie('reset_token', token, httponly=True, samesite='Lax')
            return resp

        return render_template('forgot_password.html')

    @app.route('/reset-verify', methods=['GET', 'POST'])
    def reset_verify():
        if request.method == 'POST':
            entered = request.form.get('otp', '').strip()
            token = request.cookies.get('reset_token')
            if not token:
                flash('Session expired. Start forgot flow again.', 'danger')
                return redirect(url_for('forgot'))
            try:
                data = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
            except jwt.ExpiredSignatureError:
                flash('OTP expired. Start again.', 'danger')
                return redirect(url_for('forgot'))
            except Exception:
                flash('Invalid session', 'danger')
                return redirect(url_for('forgot'))

            if entered == data.get('otp'):
                # set a pwd_reset cookie for the reset form
                reset_payload = {'email': data.get('email'), 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}
                reset_token = jwt.encode(reset_payload, app.config['JWT_SECRET'], algorithm='HS256')
                resp = make_response(redirect(url_for('reset_password')))
                resp.set_cookie('pwd_reset', reset_token, httponly=True, samesite='Lax')
                resp.set_cookie('reset_token', '', expires=0)
                return resp
            else:
                flash('Invalid OTP', 'danger')

        return render_template('verify_otp.html')

    @app.route('/reset-password', methods=['GET', 'POST'])
    def reset_password():
        token = request.cookies.get('pwd_reset')
        if not token:
            flash('Unauthorized or session expired.', 'danger')
            return redirect(url_for('forgot'))
        try:
            data = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
        except Exception:
            flash('Session expired or invalid.', 'danger')
            return redirect(url_for('forgot'))

        if request.method == 'POST':
            new_pass = request.form.get('new_password', '')
            if not new_pass or len(new_pass) < 6:
                flash('Password should be at least 6 characters', 'danger')
                return redirect(url_for('reset_password'))
            user = Employee.query.filter_by(email=data.get('email')).first()
            user.password_hash = pbkdf2_sha256.hash(new_pass)
            db.session.commit()
            flash('Password updated. Please login.', 'success')
            resp = make_response(redirect(url_for('login')))
            resp.set_cookie('pwd_reset', '', expires=0)
            return resp

        return render_template('reset_password.html')

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)