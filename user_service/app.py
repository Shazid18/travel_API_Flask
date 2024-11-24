import json
import os

from flask import Flask, request, jsonify
from flask_restx import Api, Resource, fields
from passlib.hash import pbkdf2_sha256
from jose import jwt
from werkzeug.middleware.proxy_fix import ProxyFix


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

# Configure Swagger UI
authorizations = {
    'Bearer Auth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
    },
}

api = Api(app, version='1.0', title='Travel User Service API',
          description='A simple Travel User Service API',
          authorizations=authorizations,
          security='Bearer Auth')

ns = api.namespace('api', description='User operations')

# Models for swagger documentation
user_model = api.model('User', {
    'name': fields.String(required=True, description='User full name', example='John Doe'),
    'email': fields.String(required=True, description='User email', example='john@example.com'),
    'password': fields.String(required=True, description='User password', example='password123'),
    'role': fields.String(required=True, description='User role (Admin/User)', example='User')
})

login_model = api.model('Login', {
    'email': fields.String(required=True, description='User email', example='john@example.com'),
    'password': fields.String(required=True, description='User password', example='password123')
})

profile_response_model = api.model('Profile', {
    'name': fields.String(description='User full name'),
    'email': fields.String(description='User email'),
    'role': fields.String(description='User role')
})

# Secret key for JWT
SECRET_KEY = "your-secret-key"


def load_users():
    if not os.path.exists('data/users.json'):
        os.makedirs('data', exist_ok=True)
        with open('data/users.json', 'w') as f:
            json.dump([], f)
    with open('data/users.json', 'r') as f:
        return json.load(f)


def save_users(users):
    with open('data/users.json', 'w') as f:
        json.dump(users, f, indent=4)


@ns.route('/register')
class Register(Resource):
    @ns.expect(user_model)
    @ns.doc(
        description='Register a new user',
        responses={
            201: 'User registered successfully',
            400: 'Email already registered/Invalid email format/Invalid password length'
        }
    )
    def post(self):
        """Register a new user"""
        data = request.json
        users = load_users()

        # Email validation
        if '@' not in data['email'] or '.' not in data['email']:
            api.abort(400, "Not a valid email")

        # Password length validation
        if len(data['password']) < 8:
            api.abort(400, "Password length must be 8 character or more")

        if any(user['email'] == data['email'] for user in users):
            api.abort(400, "Email already registered")

        new_user = {
            'name': data['name'],
            'email': data['email'],
            'password': pbkdf2_sha256.hash(data['password']),
            'role': data['role']
        }

        users.append(new_user)
        save_users(users)

        return {"message": "User registered successfully"}, 201


@ns.route('/login')
class Login(Resource):
    @ns.expect(login_model)
    @ns.doc(
        description='Login and get access token',
        responses={
            200: 'Login successful',
            401: 'Invalid credentials'
        }
    )
    def post(self):
        """Login with email and password"""
        data = request.json
        users = load_users()

        user = next(
            (user for user in users if user['email'] == data['email']), None)

        if user and pbkdf2_sha256.verify(data['password'], user['password']):
            token = jwt.encode(
                {'email': user['email'], 'role': user['role']},
                SECRET_KEY,
                algorithm='HS256'
            )
            return {"token": token}, 200

        api.abort(401, "Invalid credentials")


@ns.route('/profile')
class Profile(Resource):
    @ns.doc(
        description='Get user profile',
        responses={
            200: 'Success',
            401: 'Token is missing or invalid',
            404: 'User not found'
        }
    )
    @ns.marshal_with(profile_response_model)
    def get(self):
        """Get user profile information"""
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            api.abort(401, "Token is missing")

        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

        except Exception as e:
            api.abort(401, "Invalid token")

        users = load_users()
        user = next(
            (user for user in users if user['email'] == payload['email']), None)

        if user:
            return {
                'name': user['name'],
                'email': user['email'],
                'role': user['role']
            }
        api.abort(404, "User not found")


@ns.route('/users_profile')
class UsersProfile(Resource):
    @ns.doc(
        description='Get all users profiles (Admin only)',
        responses={
            200: 'Success',
            401: 'Token is missing or invalid',
            403: 'Forbidden - Admin access required'
        }
    )
    @ns.marshal_list_with(profile_response_model)
    def get(self):
        """Get all users profile information (Admin only)"""
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            api.abort(401, "Token is missing")

        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

        except Exception:
            api.abort(401, "Invalid token")

        # Check admin role after validating token
        if payload['role'] != 'Admin':
            api.abort(403, "Admin access required")

        users = load_users()
        return [{
            'name': user['name'],
            'email': user['email'],
            'role': user['role']
        } for user in users]


if __name__ == '__main__':
    app.run(port=5001, debug=True)
