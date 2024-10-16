from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
from flask_migrate import Migrate

app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize database and migrations
db.init_app(app)
migrate = Migrate(app, db)

# Home route for the index page
@app.route('/')
def home():
    return render_template('index.html')

# Registration route
# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        print(f"Username: {username}, Email: {email}, Password: {password}")  # Debug output

        
        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            print('Email address already exists. Please use a different email.', 'danger')
            return redirect(url_for('register'))
        
        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Save the user
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            print('Registration successful! Please check your email for verification.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()  # Rollback in case of error
            print('An error occurred while registering. Please try again.', 'danger')
            print(f"Error: {e}")  # Print the error for debugging

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login logic here
        pass
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
