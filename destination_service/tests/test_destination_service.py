import pytest
from unittest.mock import patch

from flask import Flask
from app import app, jwt


# Mock destinations data
mock_destinations = [
    {"id": 1, "name": "Paris", "description": "City of Light", "location": "France"},
    {"id": 2, "name": "Tokyo", "description": "Bustling Metropolis", "location": "Japan"}
]


@pytest.fixture
def client():
    """Fixture for Flask test client"""
    app.testing = True
    with app.test_client() as client:
        yield client


# Test GET /api/destinations
@patch('app.load_destinations', return_value=mock_destinations)
def test_list_destinations(mock_load, client):
    """Test GET /api/destinations"""
    response = client.get('/api/destinations')
    assert response.status_code == 200
    assert len(response.json) == 2


# Test POST /api/destinations
@patch('app.load_destinations', return_value=mock_destinations)
@patch('app.save_destinations')
def test_create_destination(mock_save, mock_load, client):
    """Test POST /api/destinations with valid admin token"""
    headers = {
        'Authorization': 'Bearer ' + jwt.encode({'role': 'Admin'}, "your-secret-key", algorithm='HS256')
    }
    data = {
        'name': 'New Destination',
        'description': 'A beautiful place',
        'location': 'New Location'
    }
    response = client.post('/api/destinations', json=data, headers=headers)
    assert response.status_code == 201
    assert response.json['name'] == 'New Destination'


# Test DELETE /api/destinations/<id>
@patch('app.load_destinations', return_value=mock_destinations)
@patch('app.save_destinations')
def test_delete_destination(mock_save, mock_load, client):
    """Test DELETE /api/destinations/<id>"""
    headers = {
        'Authorization': 'Bearer ' + jwt.encode({'role': 'Admin'}, "your-secret-key", algorithm='HS256')
    }
    response = client.delete('/api/destinations/1', headers=headers)
    assert response.status_code == 204


@patch('app.load_destinations', return_value=mock_destinations)
@patch('app.save_destinations')
def test_delete_destination_not_found(mock_save, mock_load, client):
    """Test DELETE /api/destinations/<id> with non-existent ID"""
    headers = {
        'Authorization': 'Bearer ' + jwt.encode({'role': 'Admin'}, "your-secret-key", algorithm='HS256')
    }
    response = client.delete('/api/destinations/999', headers=headers)
    assert response.status_code == 404
    assert "Destination not found" in response.json['message']


# Test Unauthorized and Invalid Scenarios
def test_create_destination_no_token(client):
    """Test POST /api/destinations with missing Authorization header"""
    data = {
        'name': 'New Destination',
        'description': 'A beautiful place',
        'location': 'New Location'
    }
    response = client.post('/api/destinations', json=data)
    assert response.status_code == 401
    assert "Token is missing" in response.json['message']


def test_create_destination_invalid_token(client):
    """Test POST /api/destinations with an invalid token"""
    headers = {
        'Authorization': 'Bearer invalidtoken'
    }
    data = {
        'name': 'New Destination',
        'description': 'A beautiful place',
        'location': 'New Location'
    }
    response = client.post('/api/destinations', json=data, headers=headers)
    assert response.status_code == 401
    assert "Invalid token" in response.json['message']


def test_delete_destination_unauthorized(client):
    """Test DELETE /api/destinations/<id> as non-admin"""
    headers = {
        'Authorization': 'Bearer ' + jwt.encode({'role': 'User'}, "your-secret-key", algorithm='HS256')
    }
    response = client.delete('/api/destinations/1', headers=headers)
    assert response.status_code == 403
    assert "Admin access required" in response.json['message']
