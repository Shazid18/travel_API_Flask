import pytest

from app import app
from jose import jwt


SECRET_KEY = "your-secret-key"


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def generate_token(payload):
    """Helper function to generate a valid JWT token"""
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def test_verify_token_valid(client):
    """Test token verification with a valid token"""
    token = generate_token({"role": "User", "username": "testuser"})
    response = client.get('/api/auth/verify',
                          headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json['valid'] is True
    assert response.json['user']['role'] == "User"
    assert response.json['user']['username'] == "testuser"


def test_verify_token_invalid(client):
    """Test token verification with an invalid token"""
    response = client.get('/api/auth/verify',
                          headers={"Authorization": "Bearer invalidtoken"})
    assert response.status_code == 401
    assert "Invalid token" in response.json['message']


def test_verify_token_missing(client):
    """Test token verification with no token"""
    response = client.get('/api/auth/verify')
    assert response.status_code == 401
    assert response.json['message'] == "Token is missing"


def test_check_role_valid(client):
    """Test role check with valid token and matching role"""
    token = generate_token({"role": "Admin"})
    response = client.get('/api/auth/check-role/Admin',
                          headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json['hasRole'] is True
    assert response.json['userRole'] == "Admin"


def test_check_role_mismatch(client):
    """Test role check with valid token but mismatched role"""
    token = generate_token({"role": "User"})
    response = client.get('/api/auth/check-role/Admin',
                          headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json['hasRole'] is False
    assert response.json['userRole'] == "User"


def test_check_role_invalid(client):
    """Test role check with an invalid token"""
    response = client.get('/api/auth/check-role/Admin',
                          headers={"Authorization": "Bearer invalidtoken"})
    assert response.status_code == 401
    assert "Invalid token" in response.json['message']
