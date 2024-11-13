import pytest
from app import app, db, User
from werkzeug.security import generate_password_hash
from flask import session  # Import session from Flask
import datetime

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # In-memory database for testing
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF protection for testing
    with app.test_client() as client:
        with app.app_context():
            db.create_all()  # Initialize in-memory database
        yield client
        with app.app_context():
            db.drop_all()  # Cleanup after the test

# Test user registration functionality
def test_register_user(client):
    """Test the user registration functionality."""
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password123'
    }, follow_redirects=True)

    assert response.status_code == 200  # After redirect, the page loads successfully
    assert b'Registration successful' in response.data

    # Verify the user exists in the database
    with app.app_context():
        user = User.query.filter_by(email='test@example.com').first()
        assert user is not None
        assert user.username == 'testuser'

def test_login_user(client):
    """Test the user login functionality."""
    # Create a test user
    hashed_password = generate_password_hash('password123', method='pbkdf2:sha256')
    with app.app_context():
        new_user = User(username='testuser', email='test@example.com', password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

    # Attempt to log in with correct credentials
    response = client.post('/login', data={
        'email': 'test@example.com',
        'password': 'password123'
    }, follow_redirects=True)
# Test OTP verification functionality
def test_verify_otp(client):
    """Test OTP verification functionality."""
    # Register and login a user first
    client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password123'
    }, follow_redirects=True)
    client.post('/login', data={
        'email': 'test@example.com',
        'password': 'password123'
    }, follow_redirects=True)

    # Mock OTP (You should ideally mock sending email or use session data)
    with client.session_transaction() as session:  # Use session_transaction to mock the session
        session['otp'] = '123456'
        session['otp_expiry'] = datetime.datetime.now() + datetime.timedelta(minutes=5)

    # Submit OTP form
    response = client.post('/verify_otp', data={
        'otp1': '1', 'otp2': '2', 'otp3': '3', 'otp4': '4', 'otp5': '5', 'otp6': '6'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'OTP verified successfully. You are now logged in!' in response.data

# Test OTP verification with incorrect OTP
def test_verify_invalid_otp(client):
    """Test OTP verification with incorrect OTP."""
    # Register and login a user first
    client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'password123'
    }, follow_redirects=True)
    client.post('/login', data={
        'email': 'test@example.com',
        'password': 'password123'
    }, follow_redirects=True)

    # Submit incorrect OTP
    response = client.post('/verify_otp', data={
        'otp1': '1', 'otp2': '2', 'otp3': '3', 'otp4': '4', 'otp5': '5', 'otp6': '7'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Invalid or expired OTP. Please try again.' in response.data
