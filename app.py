# app.py
import os
import random
import datetime
import urllib.parse
from threading import Thread

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    make_response, current_app
)
from flask_mail import Mail, Message
from passlib.hash import pbkdf2_sha256
import jwt

# local imports
from models import db, Employee

load_dotenv()

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')

    # ---------- Basic config ----------
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
    app.config['JWT_SECRET'] = os.getenv('JWT_SECRET', 'jwt-dev-secret')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///employees.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Flask-Mail configuration
    app.config.update(
        MAIL_SERVER=os.getenv('MAIL_SERVER', ''),
        MAIL_PORT=int(os.getenv('MAIL_PORT') or 587),
        MAIL_USE_SSL=(os.getenv('MAIL_USE_SSL', 'False') == 'True'),
        MAIL_USE_TLS=(os.getenv('MAIL_USE_TLS', 'True') == 'True'),
        MAIL_USERNAME=os.getenv('MAIL_USERNAME', None),
        MAIL_PASSWORD=os.getenv('MAIL_PASSWORD', None),
        MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER') or os.getenv('MAIL_USERNAME')
    )

    # Initialize extensions
    mail = Mail(app)
    db.init_app(app)

    # Make sure DB tables exist (only in simple setups; in prod use migrations)
    with app.app_context():
        try:
            db.create_all()
            app.logger.info("Database tables ensured.")
        except Exception:
            app.logger.exception("Could not create DB tables at startup.")

    # ---------- Helper functions ----------
    def gen_otp():
        """Return a 6-digit OTP as string."""
        return f"{random.randint(100000, 999999):06d}"

    def _send_async_email(app_obj, msg_obj):
        """Worker thread target: sends email inside app context and logs failures."""
        with app_obj.app_context():
            try:
                start = datetime.datetime.utcnow()
                mail.send(msg_obj)
                elapsed = (datetime.datetime.utcnow() - start).total_seconds()
                app_obj.logger.info("Email sent to %s in %.2fs", getattr(msg_obj, "recipients", []), elapsed)
            except Exception:
                app_obj.logger.exception("Async mail send failed")

    def send_email_background(app_obj, msg_obj):
        """Spawn a daemon thread to send email so request thread isn't blocked."""
        try:
            thr = Thread(target=_send_async_email, args=(app_obj, msg_obj), daemon=True)
            thr.start()
        except Exception:
            app_obj.logger.exception("Failed to start email thread")
            # fallback: try synchronous send (still wrapped in try/except)
            try:
                with app_obj.app_context():
                    mail.send(msg_obj)
            except Exception:
                app_obj.logger.exception("Fallback synchronous mail send failed")

    def make_jwt(payload, expires_minutes=None):
        payload = dict(payload)
        if expires_minutes:
            payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(minutes=expires_minutes)
        return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')

    def decode_jwt_safe(token):
        """Safely decode a JWT token, return payload or raise."""
        # URL decode in case cookie encoding/transport altered the token
        token = urllib.parse.unquote(token)
        try:
            data = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
            return data
        except jwt.ExpiredSignatureError:
            raise
        except Exception as exc:
            # Re-raise to let callers handle with flash/redirect
            raise

    # ---------- Routes ----------
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
                'otp': otp
            }
            token = make_jwt(payload, expires_minutes=7)

            # send OTP email asynchronously
            try:
                msg = Message('Your Login OTP', recipients=[user.email])
                msg.body = (
                    f"Hello {user.name},\n\n"
                    f"Your OTP to complete login: {otp}\n"
                    f"This code expires in 7 minutes.\n\n"
                    "If you did not request this, ignore."
                )
                send_email_background(app, msg)
                app.logger.info("Queued OTP email for %s", user.email)
            except Exception:
                app.logger.exception('Failed to queue OTP email')
                flash('Failed to send OTP. Contact admin.', 'danger')
                return redirect(url_for('login'))

            resp = make_response(redirect(url_for('verify_otp')))
            resp.set_cookie('otp_token', token, httponly=True, samesite='Lax')
            return resp

        return render_template('login.html')

    @app.route('/verify-otp', methods=['GET', 'POST'])
    def verify_otp():
        if request.method == 'POST':
            entered = request.form.get('otp', '').strip()
        else:
            entered = None

        token = request.cookies.get('otp_token')
        if not token:
            flash('OTP session expired. Please login again.', 'danger')
            return redirect(url_for('login'))

        try:
            data = decode_jwt_safe(token)
        except jwt.ExpiredSignatureError:
            flash('OTP expired. Please login again.', 'danger')
            return redirect(url_for('login'))
        except Exception:
            app.logger.exception("OTP token decode failed")
            flash('OTP validation failed. Please login again.', 'danger')
            return redirect(url_for('login'))

        if request.method == 'POST':
            if entered == data.get('otp'):
                # issue auth token (2-hour expiry)
                auth_payload = {
                    'email': data.get('email')
                }
                auth_token = make_jwt(auth_payload, expires_minutes=120)
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
                decode_jwt_safe(token)
            except Exception:
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return wrapper

    @app.route('/dashboard')
    @auth_required
    def dashboard():
        # example dashboard, adapt per your project
        return render_template('dashboard.html')

    # Forgot password -> send reset OTP
    @app.route('/forgot', methods=['GET', 'POST'])
    def forgot():
        if request.method == 'POST':
            emp_id = request.form.get('employee_id', '').strip()
            email = request.form.get('email', '').strip()

            if not emp_id or not email:
                flash('Provide Employee ID and Email', 'danger')
                return redirect(url_for('forgot'))

            user = Employee.query.filter_by(employee_id=emp_id, email=email).first()
            if not user:
                flash('Employee ID and Email do not match', 'danger')
                return redirect(url_for('forgot'))

            otp = gen_otp()
            payload = {'email': user.email, 'otp': otp}
            token = make_jwt(payload, expires_minutes=10)

            try:
                msg = Message('Password Reset OTP', recipients=[user.email])
                msg.body = (
                    f"Hello {user.name},\n\nYour password reset OTP: {otp}\n"
                    "Expires in 10 minutes.\n\nIf you did not request this, ignore."
                )
                send_email_background(app, msg)
                app.logger.info("Queued password reset OTP for %s", user.email)
            except Exception:
                app.logger.exception('Failed to queue reset OTP')
                flash('Could not send reset OTP. Contact admin.', 'danger')

            resp = make_response(redirect(url_for('reset_verify')))
            resp.set_cookie('reset_token', token, httponly=True, samesite='Lax')
            return resp

        return render_template('forgot_password.html')

    @app.route('/reset-verify', methods=['GET', 'POST'])
    def reset_verify():
        if request.method == 'POST':
            entered = request.form.get('otp', '').strip()
        else:
            entered = None

        token = request.cookies.get('reset_token')
        if not token:
            flash('Session expired. Start forgot flow again.', 'danger')
            return redirect(url_for('forgot'))

        try:
            data = decode_jwt_safe(token)
        except jwt.ExpiredSignatureError:
            flash('OTP expired. Start again.', 'danger')
            return redirect(url_for('forgot'))
        except Exception:
            app.logger.exception("Reset token decode failed")
            flash('Invalid session', 'danger')
            return redirect(url_for('forgot'))

        if request.method == 'POST':
            if entered == data.get('otp'):
                reset_payload = {'email': data.get('email')}
                reset_token = make_jwt(reset_payload, expires_minutes=15)
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
            data = decode_jwt_safe(token)
        except Exception:
            flash('Session expired or invalid.', 'danger')
            return redirect(url_for('forgot'))

        if request.method == 'POST':
            new_pass = request.form.get('new_password', '')
            if not new_pass or len(new_pass) < 6:
                flash('Password should be at least 6 characters', 'danger')
                return redirect(url_for('reset_password'))
            user = Employee.query.filter_by(email=data.get('email')).first()
            if not user:
                flash('User not found', 'danger')
                return redirect(url_for('forgot'))

            user.password_hash = pbkdf2_sha256.hash(new_pass)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                app.logger.exception("Failed to update password")
                flash('Could not update password. Try again later.', 'danger')
                return redirect(url_for('reset_password'))

            flash('Password updated. Please login.', 'success')
            resp = make_response(redirect(url_for('login')))
            resp.set_cookie('pwd_reset', '', expires=0)
            return resp

        return render_template('reset_password.html')

    # Simple health check endpoint
    @app.route('/health')
    def health():
        return "OK", 200

    # Optional error handlers (useful for logging)
    @app.errorhandler(404)
    def not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(e):
        current_app.logger.exception("Server error: %s", e)
        return render_template('500.html'), 500

    return app


if __name__ == "__main__":
    # for local dev only. In production use gunicorn with create_app() factory.
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)), debug=(os.getenv("FLASK_DEBUG") == "1"))
