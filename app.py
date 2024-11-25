from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from models import db, User
from flask_migrate import Migrate
from functools import wraps
import pytz  # Import pytz for timezone handling
import secrets
import re
from datetime import datetime

from itsdangerous import URLSafeTimedSerializer

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config.from_object('config.Config')

# Setup Flask-Mail for Email Integration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'yk26391@gmail.com'  # Use your Gmail address
app.config['MAIL_PASSWORD'] = 'nyug slnj gkvi zsgg'  # Use your Gmail password or App Password
app.config['MAIL_DEFAULT_SENDER'] = 'yk26391@gmail.com'


mail = Mail(app)
    
# Initialize database and migrations
db.init_app(app)
migrate = Migrate(app, db)

# Helper function to check if the user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_token' not in session:
            flash('You need to be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Generate OTP and send email
def send_otp(user_email):
    otp = secrets.token_hex(3)  # Generates a 6-digit OTP
    otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)  # OTP expiration time: 5 minutes
    
    # Store OTP and expiration in the session
    session['otp'] = otp
    session['otp_expiry'] = otp_expiry
    
    # Send OTP to user via email
    msg = Message("Your OTP Code", recipients=[user_email])
    msg.body = f"Your OTP code is {otp}. It will expire in 5 minutes."
    
    try:
        mail.send(msg)
        flash('OTP sent to your email!', 'success')
    except Exception as e:
        flash(f'Failed to send OTP: {str(e)}', 'danger')

# Home route for the index page
@app.route('/')
def home():
    return render_template('index.html')

# Generate a confirmation token
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

# Confirm the token
def confirm_token(token, expiration=3600):  # Token expires in 1 hour
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except Exception:
        return False
    return email
# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Input validation
        if len(username) <= 3:
            flash('Username must be at least 4 characters long.', 'danger')
            return redirect(url_for('register'))

        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            flash('Invalid email address format.', 'danger')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return redirect(url_for('register'))

        # Check for at least one capital letter and one special character
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one uppercase letter.', 'danger')
            return redirect(url_for('register'))
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            flash('Password must contain at least one special character.', 'danger')
            return redirect(url_for('register'))

        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already exists. Please use a different email.', 'danger')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Generate verification token
        verification_token = secrets.token_hex(16)

        # Save the user
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            email_verification_token=verification_token,
            email_verification_sent_at=datetime.utcnow()
        )

        try:
            db.session.add(new_user)
            db.session.commit()

            # Send verification email
            send_verification_email(email, verification_token)

            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while registering: {e}', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

def send_verification_email(email, token):
    verification_link = url_for('verify_email', token=token, _external=True)
    msg = Message(
        "Email Verification - Your App",
        recipients=[email],
        body=f"Please click the following link to verify your email address:\n\n{verification_link}\n\nIf you did not register, please ignore this email."
    )
    try:
        mail.send(msg)
        flash('Verification email sent. Please check your inbox.', 'info')
    except Exception as e:
        flash(f'Failed to send verification email: {e}', 'danger')
@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    user = User.query.filter_by(email_verification_token=token).first()

    if not user:
        flash('Invalid or expired verification link.', 'danger')
        return redirect(url_for('register'))

   
    user.is_verified = True
    user.email_verification_token = None 
    user.email_verification_sent_at = None
    db.session.commit()

    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()

    if user.email_verified:
        flash('Account already confirmed. Please log in.', 'success')
    else:
        user.email_verified = True
        db.session.commit()
        flash('Your email has been confirmed. Thank you!', 'success')

    return redirect(url_for('login'))

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "10 per hour"] 
)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit to 5 login attempts per minute
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email not registered. Please sign up first.', 'warning')
            return redirect(url_for('login'))

        if not user.is_verified:
            flash('Your email is not verified. Please verify your email first.', 'danger')
            return redirect(url_for('login'))

        if user and check_password_hash(user.password, password):
            session['user_token'] = secrets.token_hex(16)
            session['user_id'] = user.id
            return redirect(url_for('sample'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/verify_otp', methods=['GET', 'POST'])
@login_required
def verify_otp():
    if request.method == 'POST':
        # Concatenate OTP from form inputs
        otp = ''.join([request.form.get(f'otp{i}') for i in range(1, 7)])

        # Make current_time aware by setting it to UTC (or your desired timezone)
        current_time = datetime.datetime.now(pytz.utc)  # or use your preferred timezone

        # Check OTP validity
        if otp == session.get('otp') and current_time < session.get('otp_expiry'):
            flash('OTP verified successfully. You are now logged in!', 'success')
            return redirect(url_for('sample'))  # Redirect to the sample page
        else:
            flash('Invalid or expired OTP. Please try again.', 'danger')

    return render_template('verify_otp.html')
# Sample page after successful login
@app.route('/sample')
@login_required
def sample():
    return render_template('sample.html')

# Logout route
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_token', None)
    session.pop('user_id', None)
    session.pop('otp', None)  # Clear OTP session on logout
    session.pop('otp_expiry', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))
# Resend OTP route
@app.route('/resend_otp', methods=['GET'])
@login_required
def resend_otp():
    user = User.query.get(session['user_id'])
    
    if user:
        send_otp(user.email)  # Re-send OTP to the user's email
        flash('OTP has been resent to your email!', 'success')
        return redirect(url_for('verify_otp'))  # Redirect back to the OTP verification page
    
    flash('User not found. Please login again.', 'danger')
    return redirect(url_for('login'))  # Redirect to login if user not found


if __name__ == '__main__':
    app.run(debug=True)
