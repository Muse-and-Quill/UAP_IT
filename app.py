# app.py
import os
import random
import datetime
import urllib.parse
import smtplib
import requests
from threading import Thread

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    make_response, current_app
)
from flask_mail import Mail, Message
from passlib.hash import pbkdf2_sha256
import jwt

# local models: ensure models.py exposes `db` and `Employee`
from models import db, Employee

load_dotenv()


def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')

    # ---------- CONFIG ----------
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
    app.config['JWT_SECRET'] = os.getenv('JWT_SECRET', 'jwt-dev-secret')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///employees.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Flask-Mail config (Gmail example: STARTTLS on 587)
    app.config.update(
        MAIL_SERVER=os.getenv('MAIL_SERVER', ''),
        MAIL_PORT=int(os.getenv('MAIL_PORT') or 587),
        MAIL_USE_TLS=(os.getenv('MAIL_USE_TLS', 'True') == 'True'),
        MAIL_USE_SSL=(os.getenv('MAIL_USE_SSL', 'False') == 'True'),
        MAIL_USERNAME=os.getenv('MAIL_USERNAME', None),
        MAIL_PASSWORD=os.getenv('MAIL_PASSWORD', None),
        MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER') or os.getenv('MAIL_USERNAME')
    )


    # Initialize extensions
    mail = Mail(app)
    db.init_app(app)

    # Ensure DB tables exist (only for small/simple setups)
    with app.app_context():
        try:
            db.create_all()
            app.logger.info("Database tables ensured.")
        except Exception:
            app.logger.exception("Could not create DB tables at startup.")

    # ---------- Helpers ----------

    def gen_otp():
        """Generate a 6-digit OTP."""
        return f"{random.randint(100000, 999999):06d}"

    def make_jwt(payload: dict, expires_minutes: int = None):
        p = dict(payload)
        if expires_minutes:
            p['exp'] = datetime.datetime.utcnow() + datetime.timedelta(minutes=expires_minutes)
        token = jwt.encode(p, app.config['JWT_SECRET'], algorithm='HS256')
        # If PyJWT returns bytes in your environment, decode to str
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        return token

    def decode_jwt_safe(token: str):
        """Decode JWT safely; URL-decode token first (cookies sometimes URL encoded)."""
        token = urllib.parse.unquote(token)
        data = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
        return data

    # ---------- Email sending helpers (async with SendGrid fallback) ----------

    def _send_via_sendgrid(to_email: str, subject: str, body: str):
        """Send email via SendGrid HTTP API. Raises on error."""
        api_key = os.getenv('SENDGRID_API_KEY')
        if not api_key:
            raise RuntimeError("SENDGRID_API_KEY is not set")
        payload = {
            "personalizations": [{"to": [{"email": to_email}], "subject": subject}],
            "from": {"email": os.getenv('MAIL_DEFAULT_SENDER')},
            "content": [{"type": "text/plain", "value": body}]
        }
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        r = requests.post("https://api.sendgrid.com/v3/mail/send", headers=headers, json=payload, timeout=10)
        r.raise_for_status()
        return r

    def _send_async_email(app_obj, msg_obj):
        """Attempt SMTP send (Flask-Mail). If it fails, try SendGrid fallback if available."""
        with app_obj.app_context():
            try:
                app_obj.logger.info("Async mail: starting -> to=%s subject=%s",
                                    getattr(msg_obj, "recipients", []), getattr(msg_obj, "subject", ""))
                mail.send(msg_obj)
                app_obj.logger.info("Async mail: success -> to=%s", getattr(msg_obj, "recipients", []))
                return
            except smtplib.SMTPAuthenticationError as ex:
                app_obj.logger.exception("SMTP auth error: %s", ex)
            except smtplib.SMTPConnectError as ex:
                app_obj.logger.exception("SMTP connect error: %s", ex)
            except smtplib.SMTPRecipientsRefused as ex:
                app_obj.logger.exception("SMTP recipients refused: %s", ex)
            except Exception as ex:
                app_obj.logger.exception("Async mail send failed (SMTP): %s", ex)

            # SMTP failed — attempt HTTP fallback via SendGrid if configured
            try:
                recipients = getattr(msg_obj, "recipients", []) or []
                to = recipients[0] if recipients else None
                if to and os.getenv('SENDGRID_API_KEY'):
                    app_obj.logger.info("Async mail: attempting SendGrid fallback to %s", to)
                    _send_via_sendgrid(to, getattr(msg_obj, 'subject', ''), getattr(msg_obj, 'body', ''))
                    app_obj.logger.info("Async mail: SendGrid fallback success -> to=%s", to)
                else:
                    app_obj.logger.warning("Async mail: no SendGrid API key or recipient; fallback not attempted.")
            except Exception:
                app_obj.logger.exception("Async mail: SendGrid fallback failed")

    def send_email_background(app_obj, msg_obj):
        """Spawn a daemon thread to send email asynchronously."""
        try:
            thr = Thread(target=_send_async_email, args=(app_obj, msg_obj), daemon=True)
            thr.start()
        except Exception:
            app_obj.logger.exception("Failed to start email sending thread")

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

            otp = gen_otp()
            payload = {'email': user.email, 'otp': otp}
            token = make_jwt(payload, expires_minutes=7)

            # Queue email asynchronously
            try:
                msg = Message('Your Login OTP', recipients=[user.email])
                msg.body = (
                    f"Hello {user.name},\n\n"
                    f"Your OTP to complete login: {otp}\n"
                    "This code expires in 7 minutes.\n\n"
                    "If you did not request this, ignore."
                )
                send_email_background(app, msg)
                app.logger.info("Queued OTP email for %s", user.email)
            except Exception:
                app.logger.exception("Failed to queue OTP email")
                flash('Failed to send OTP. Contact admin.', 'danger')
                return redirect(url_for('login'))

            resp = make_response(redirect(url_for('verify_otp')))
            resp.set_cookie('otp_token', token, httponly=True, samesite='Lax')
            return resp

        return render_template('login.html')

    @app.route('/verify-otp', methods=['GET', 'POST'])
    def verify_otp():
        entered = None
        if request.method == 'POST':
            entered = request.form.get('otp', '').strip()

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
                auth_token = make_jwt({'email': data.get('email')}, expires_minutes=120)
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
        return render_template('dashboard.html')

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
        entered = None
        if request.method == 'POST':
            entered = request.form.get('otp', '').strip()

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
                reset_token = make_jwt({'email': data.get('email')}, expires_minutes=15)
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

    # Temporary debug route - synchronous send so exceptions surface in response/logs.
    # Remove this route after debugging SMTP/SendGrid.
    @app.route('/_debug/send-test-email')
    def send_test_email():
        to_addr = request.args.get('to') or os.getenv('DEV_TEST_EMAIL') or 'your-email@example.com'
        subject = "UAP test email"
        body = "This is a test email sent by the UAP server (debug endpoint)."
        try:
            msg = Message(subject, recipients=[to_addr])
            msg.body = body
            # send synchronously to capture exceptions immediately
            mail.send(msg)
            app.logger.info("DEBUG: sync test email sent to %s", to_addr)
            return f"Test email sent to {to_addr}", 200
        except Exception as e:
            app.logger.exception("DEBUG: test email failed")
            return f"Test email failed: {type(e).__name__} - {e}", 500

    @app.route('/health')
    def health():
        return "OK", 200

    # Error handlers
    @app.errorhandler(404)
    def not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(e):
        current_app.logger.exception("Server error: %s", e)
        return render_template('500.html'), 500

    return app


if __name__ == "__main__":
    app = create_app()
    debug_mode = (os.getenv('FLASK_DEBUG', '0') == '1')
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)), debug=debug_mode)
