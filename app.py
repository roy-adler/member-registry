from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime
import smtplib
import logging
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    with app.app_context():
        db.create_all()
        ensure_admin_exists()
        mail_server = app.config.get('MAIL_SERVER', '')
        mail_user = app.config.get('MAIL_USERNAME', '')
        if mail_server and mail_user:
            logger.info(f'SMTP configured: server={mail_server}, port={app.config.get("MAIL_PORT")}, user={mail_user}')
        else:
            logger.info('SMTP not configured — email confirmation will use manual fallback')

    register_routes(app)
    return app


class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    address = db.Column(db.String(250), nullable=True, default='')
    phone = db.Column(db.String(50), nullable=True, default='')
    confirmed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Admin, int(user_id))


def ensure_admin_exists():
    from flask import current_app
    admin = Admin.query.filter_by(username=current_app.config['ADMIN_USERNAME']).first()
    if not admin:
        admin = Admin(username=current_app.config['ADMIN_USERNAME'])
        admin.set_password(current_app.config['ADMIN_PASSWORD'])
        db.session.add(admin)
        db.session.commit()


def generate_confirmation_token(email, secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(email, salt='email-confirm')


def verify_token(token, secret_key, max_age=3600):
    serializer = URLSafeTimedSerializer(secret_key)
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=max_age)
        return email
    except (SignatureExpired, BadSignature):
        return None


def send_email(app, to, subject, html_body):
    server_cfg = app.config.get('MAIL_SERVER', '')
    username = app.config.get('MAIL_USERNAME', '')
    if not server_cfg or not username:
        logger.info(f'Email to {to} skipped — SMTP not configured')
        return False
    try:
        sender = app.config.get('MAIL_SENDER') or username
        port = app.config.get('MAIL_PORT', 587)
        logger.info(f'Sending email to={to}, subject="{subject}", server={server_cfg}:{port}, from={sender}')

        msg = MIMEMultipart('alternative')
        msg['From'] = sender
        msg['To'] = to
        msg['Subject'] = subject
        msg.attach(MIMEText(html_body, 'html'))

        with smtplib.SMTP(server_cfg, port, timeout=10) as server:
            server.set_debuglevel(0)
            if app.config.get('MAIL_USE_TLS', True):
                server.starttls()
            server.login(username, app.config['MAIL_PASSWORD'])
            server.send_message(msg)

        logger.info(f'Email sent successfully to {to}')
        return True
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f'SMTP auth failed for {username}: {e}')
        return False
    except smtplib.SMTPException as e:
        logger.error(f'SMTP error sending to {to}: {e}')
        return False
    except Exception as e:
        logger.error(f'Failed to send email to {to}: {type(e).__name__}: {e}')
        return False


def register_routes(app):

    @app.route('/')
    def index():
        return render_template('register.html')

    @app.route('/register', methods=['POST'])
    def register():
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        address = request.form.get('address', '').strip()
        phone = request.form.get('phone', '').strip()

        if not all([name, email]):
            flash('Name and email are required.', 'error')
            return redirect(url_for('index'))

        existing = Member.query.filter_by(email=email).first()
        if existing and existing.confirmed:
            flash('This email address is already registered.', 'error')
            return redirect(url_for('index'))

        if existing and not existing.confirmed:
            existing.name = name
            existing.address = address
            existing.phone = phone
        else:
            member = Member(name=name, email=email, address=address, phone=phone)
            db.session.add(member)

        db.session.commit()

        token = generate_confirmation_token(email, app.config['SECRET_KEY'])
        confirm_url = url_for('confirm_email', token=token, _external=True)

        email_sent = send_email(
            app, email, 'Confirm your registration',
            f'<h2>Confirm your email</h2>'
            f'<p>Please click the link below to confirm your registration:</p>'
            f'<p><a href="{confirm_url}">Confirm Email</a></p>'
            f'<p>The link is valid for 1 hour.</p>'
        )

        return render_template('confirmation_sent.html',
                               confirm_url=confirm_url, email=email, email_sent=email_sent)

    @app.route('/confirm/<token>')
    def confirm_email(token):
        email = verify_token(token, app.config['SECRET_KEY'])
        if not email:
            flash('The confirmation link is invalid or expired.', 'error')
            return redirect(url_for('index'))

        member = Member.query.filter_by(email=email).first()
        if not member:
            flash('Member not found.', 'error')
            return redirect(url_for('index'))

        if member.confirmed:
            flash('Email has already been confirmed.', 'info')
        else:
            member.confirmed = True
            db.session.commit()
            flash('Email confirmed successfully! You are now registered.', 'success')

        return redirect(url_for('index'))

    @app.route('/delete-request', methods=['GET', 'POST'])
    def delete_request():
        if request.method == 'POST':
            email = request.form.get('email', '').strip()
            member = Member.query.filter_by(email=email, confirmed=True).first()
            if member:
                token = generate_confirmation_token(email, app.config['SECRET_KEY'])
                delete_url = url_for('delete_confirm', token=token, _external=True)

                email_sent = send_email(
                    app, email, 'Confirm data deletion',
                    f'<h2>Confirm Deletion</h2>'
                    f'<p>Click the link below to permanently delete your data:</p>'
                    f'<p><a href="{delete_url}">Delete My Data</a></p>'
                    f'<p>The link is valid for 1 hour.</p>'
                )

                return render_template('delete_sent.html',
                                       delete_url=delete_url, email=email, email_sent=email_sent)
            else:
                flash('No registration found with this email address.', 'error')
        return render_template('delete_request.html')

    @app.route('/delete-confirm/<token>')
    def delete_confirm(token):
        email = verify_token(token, app.config['SECRET_KEY'])
        if not email:
            flash('The link is invalid or expired.', 'error')
            return redirect(url_for('index'))

        member = Member.query.filter_by(email=email).first()
        if member:
            db.session.delete(member)
            db.session.commit()
            flash('Your data has been successfully deleted.', 'success')
        else:
            flash('Member not found.', 'error')

        return redirect(url_for('index'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            admin = Admin.query.filter_by(username=username).first()
            if admin and admin.check_password(password):
                login_user(admin)
                return redirect(url_for('admin_dashboard'))
            flash('Invalid credentials.', 'error')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Successfully logged out.', 'success')
        return redirect(url_for('index'))

    @app.route('/admin')
    @login_required
    def admin_dashboard():
        members = Member.query.filter_by(confirmed=True).order_by(Member.created_at.desc()).all()
        pending = Member.query.filter_by(confirmed=False).order_by(Member.created_at.desc()).all()
        return render_template('admin.html', members=members, pending=pending)

    @app.route('/admin/edit/<int:member_id>', methods=['GET', 'POST'])
    @login_required
    def admin_edit(member_id):
        member = db.session.get(Member, member_id)
        if not member:
            abort(404)
        if request.method == 'POST':
            member.name = request.form.get('name', '').strip()
            member.email = request.form.get('email', '').strip()
            member.address = request.form.get('address', '').strip()
            member.phone = request.form.get('phone', '').strip()
            db.session.commit()
            flash('Member updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_edit.html', member=member)

    @app.route('/admin/delete/<int:member_id>', methods=['POST'])
    @login_required
    def admin_delete(member_id):
        member = db.session.get(Member, member_id)
        if member:
            db.session.delete(member)
            db.session.commit()
            flash('Member deleted successfully.', 'success')
        return redirect(url_for('admin_dashboard'))


app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
