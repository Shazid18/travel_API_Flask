import json
from unittest import mock

import pytest
from passlib.hash import pbkdf2_sha256
from jose import jwt
from flask_jwt_extended import JWTManager

from app import app, load_users, save_users



SECRET_KEY = "your-secret-key"

# Mocked users file data for testing
MOCK_USERS = [
    {
        'name': 'John Doe',
        'email': 'john@example.com',
        'password': pbkdf2_sha256.hash('password123'),
        'role': 'User'
    }
]

# Flask app for testing


@pytest.fixture
def client():
    # Create a test client for the Flask app
    app.config['TESTING'] = True
    app.config['DEBUG'] = False
    client = app.test_client()
    yield client


user_data = {
    "username": "testuser",
    "email": "test@example.com",
    "password": pbkdf2_sha256.hash('password123'),
    "role": "Admin"
}


def generate_token(user_data):
    payload = {
        "username": user_data["username"],
        "email": user_data["email"],
        "role": user_data["role"]
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token


# Mocking load_users and save_users
@pytest.fixture(autouse=True)
def mock_load_save_users():
    with mock.patch('app.load_users', return_value=MOCK_USERS):
        with mock.patch('app.save_users') as mock_save:
            yield mock_save

# Test Register User - Success


def test_register_user_success(client, mock_load_save_users):
    # Test data for registration
    new_user = {
        'name': 'Jane Doe',
        'email': 'jane@example.com',
        'password': 'password123',
        'role': 'User'
    }

    response = client.post('/api/register', json=new_user)

    # Check if status code is 201 (created)
    assert response.status_code == 201
    assert json.loads(response.data)[
        'message'] == 'User registered successfully'

# Test Register User - Duplicate


def test_register_user_duplicate(client):
    # Try registering with an already existing email
    duplicate_user = {
        'name': 'Jane Doe',
        'email': 'john@example.com',  # already exists in MOCK_USERS
        'password': 'password123',
        'role': 'User'
    }

    response = client.post('/api/register', json=duplicate_user)

    # Check if status code is 400 (Bad Request)
    assert response.status_code == 400
    assert json.loads(response.data)['message'] == 'Email already registered'

# Test Register User - Invalid Email


def test_register_invalid_user_email(client):
    # Try registering with an invalid email
    invalid_email = {
        'name': 'Jane Doe',
        'email': 'johnexamplecom',  # invalid email in MOCK_USERS
        'password': 'password123',
        'role': 'User'
    }

    response = client.post('/api/register', json=invalid_email)

    # Check if status code is 400 (Bad Request)
    assert response.status_code == 400
    assert json.loads(response.data)['message'] == 'Not a valid email'

# Test Register User - Invalid Password Length


def test_register_invalid_password_length(client):
    # Try registering with an invalid email
    invalid_Password_Length = {
        'name': 'Jane Doe',
        'email': 'johne@xample.com',
        'password': 'pass12',  # invalid length of password in MOCK_USERS
        'role': 'User'
    }

    response = client.post('/api/register', json=invalid_Password_Length)

    # Check if status code is 400 (Bad Request)
    assert response.status_code == 400
    assert json.loads(response.data)[
        'message'] == 'Password length must be 8 character or more'

# Test Login - Success


def test_login_success(client):
    login_data = {
        'email': 'john@example.com',
        'password': 'password123'
    }

    response = client.post('/api/login', json=login_data)

    # Check if status code is 200 and token is returned
    assert response.status_code == 200
    assert 'token' in json.loads(response.data)

# Test Login - Invalid Credentials


def test_login_invalid_credentials(client):
    login_data = {
        'email': 'john@example.com',
        'password': 'wrongpassword'
    }

    response = client.post('/api/login', json=login_data)

    # Check if status code is 401 (Unauthorized)
    assert response.status_code == 401
    assert json.loads(response.data)['message'] == 'Invalid credentials'

# Test Profile - Success


def test_profile_success(client):
    # Create a valid JWT token for the user
    token = jwt.encode({'email': 'john@example.com',
                       'role': 'User'}, 'your-secret-key', algorithm='HS256')

    response = client.get(
        '/api/profile', headers={'Authorization': f'Bearer {token}'})

    # Check if status code is 200 and user data is returned
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['email'] == 'john@example.com'
    assert data['role'] == 'User'

# Test Profile - Missing Token


def test_profile_missing_token(client):
    response = client.get('/api/profile')

    # Check if status code is 401 (Unauthorized)
    assert response.status_code == 401
    assert json.loads(response.data)['message'] == 'Token is missing'

# Test Profile - Invalid Token


def test_profile_invalid_token(client):
    # Send an invalid token
    invalid_token = 'invalid.token.here'

    response = client.get(
        '/api/profile', headers={'Authorization': f'Bearer {invalid_token}'})

    # Check if status code is 401 (Unauthorized)
    assert response.status_code == 401
    assert json.loads(response.data)['message'] == 'Invalid token'

# Test Profile - User Not Found


def test_profile_user_not_found(client):
    # Create a valid JWT token with an email not in MOCK_USERS
    token = jwt.encode({'email': 'nonexistent@example.com',
                       'role': 'User'}, 'your-secret-key', algorithm='HS256')

    response = client.get(
        '/api/profile', headers={'Authorization': f'Bearer {token}'})

    # Check if status code is 404 (Not Found)
    assert response.status_code == 404
    # assert json.loads(response.data)['message'] == 'User not found'
    assert "User not found" in json.loads(response.data)['message']

# Test UsersProfile - Valid Admin Token


def test_get_users_profile_with_valid_admin_token(client):
    token = generate_token(
        {"username": "testuser", "email": "test@example.com", "role": "Admin"})

    # Test valid Admin access to '/users_profile' endpoint
    response = client.get(
        '/api/users_profile',
        headers={'Authorization': f'Bearer {token}'}
    )

    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert 'name' in data[0]
    assert 'email' in data[0]
    assert 'role' in data[0]


# Test UsersProfile - Invalid Token
def test_get_users_profile_with_invalid_token(client):
    # Test access with an invalid token
    response = client.get(
        '/api/users_profile',
        headers={'Authorization': 'Bearer invalidtoken'}
    )
    assert response.status_code == 401
    assert b"Invalid token" in response.data


# Test UsersProfile - Missing Token
def test_get_users_profile_with_missing_token(client):
    # Test access without providing token
    response = client.get('/api/users_profile')
    assert response.status_code == 401
    assert b"Token is missing" in response.data


# Test UsersProfile - Invalid Admin Token
def test_get_users_profile_with_non_admin_token(client):
    # Test access with a non-Admin token
    token = generate_token(
        {"username": "testuser", "email": "test@example.com", "role": "User"})
    response = client.get(
        '/api/users_profile',
        headers={'Authorization': f'Bearer {token}'}
    )
    assert response.status_code == 403
    assert b"Admin access required" in response.data
