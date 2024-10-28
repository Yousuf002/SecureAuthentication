import unittest
from app import create_app, db
from models import User

class FlaskAppTestCase(unittest.TestCase):
    def setUp(self):
        """Set up the test client and the database."""
        self.app = create_app('testing')  # Use the testing configuration
        self.client = self.app.test_client()
        with self.app.app_context():
            db.create_all()  # Create the database tables

    def tearDown(self):
        """Clean up the database after each test."""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()  # Drop all the database tables

    def test_home_page(self):
        """Test the home page loads successfully."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome', response.data)  # Check for specific content

    def test_register_user(self):
        """Test user registration."""
        response = self.client.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123'
        })
        with self.app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
        self.assertEqual(response.status_code, 302)  # Redirect after registration
        self.assertIsNotNone(user)  # User should be created in the database

    def test_register_user_existing_email(self):
        """Test registration with an existing email."""
        self.client.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123'
        })
        response = self.client.post('/register', data={
            'username': 'newuser',
            'email': 'test@example.com',
            'password': 'password123'
        })
        self.assertEqual(response.status_code, 302)  # Redirect after failed registration
        self.assertIn(b'Email address already exists', response.data)

    def test_login_user(self):
        """Test user login."""
        self.client.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123'
        })
        response = self.client.post('/login', data={
            'email': 'test@example.com',
            'password': 'password123'
        })
        self.assertEqual(response.status_code, 302)  # Redirect after successful login
        self.assertIn(b'Login successful', response.data)

    def test_login_invalid_user(self):
        """Test login with invalid credentials."""
        response = self.client.post('/login', data={
            'email': 'invalid@example.com',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 302)  # Redirect after failed login
        self.assertIn(b'Invalid email or password', response.data)

    def test_sample_page_access_without_login(self):
        """Test access to the sample page without login."""
        response = self.client.get('/sample')
        self.assertEqual(response.status_code, 302)  # Should redirect to login
        self.assertIn(b'You need to log in first', response.data)

    def test_logout_user(self):
        """Test user logout."""
        self.client.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123'
        })
        self.client.post('/login', data={
            'email': 'test@example.com',
            'password': 'password123'
        })
        response = self.client.post('/logout')
        self.assertEqual(response.status_code, 302)  # Redirect after logout
        self.assertIn(b'You have been logged out', response.data)

if __name__ == '__main__':
    unittest.main()
