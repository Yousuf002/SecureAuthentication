from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from models import db, User
from flask_migrate import Migrate
from functools import wraps
import pytz  # Import pytz for timezone handling
import secrets
import re
import datetime

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
        
        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already exists. Please use a different email.', 'danger')
            return redirect(url_for('register'))
        
        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Save the user
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please check your email for verification.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while registering. Please try again. Reason: ' + str(e), 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Fetch the user from the database
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Email not registered. Please sign up first.', 'warning')
            return redirect(url_for('login'))
        
        if user and check_password_hash(user.password, password):
            # Generate a unique token for this session
            session['user_token'] = secrets.token_hex(16)
            session['user_id'] = user.id
            send_otp(user.email)  # Send OTP after login

            return redirect(url_for('verify_otp'))  # Redirect to OTP verification page
        
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
