from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
from flask_migrate import Migrate
from functools import wraps
import secrets

app = Flask(__name__)
app.config.from_object('config.Config')

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

# Home route for the index page
@app.route('/')
def home():
    return render_template('index.html')

# Make route for sample.html page with login restriction
@app.route('/sample')
@login_required
def sample():
    return render_template('sample.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
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
            flash('An error occurred while registering. Please try again.', 'danger')
            print(f"Error: {e}")

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Fetch the user from the database
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            # Generate a unique token for this session
            session['user_token'] = secrets.token_hex(16)
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            
            # Placeholder for future OTP functionality
            flash('OTP verification required (coming soon)', 'info')
            return redirect(url_for('sample'))
        
        else:
            flash('Invalid email or password. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

# Logout route to clear session
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_token', None)
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
