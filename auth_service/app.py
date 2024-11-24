from flask import Flask
from flask import request
from flask import jsonify
from flask_restx import Api
from flask_restx import Resource
from flask_restx import fields
from jose import jwt, JWTError
import requests
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps

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

api = Api(app, version='1.0', title='Authentication Service API',
          description='A service for JWT token verification and role checking',
          authorizations=authorizations,
          security='Bearer Auth')

ns = api.namespace('api/auth', description='Authentication operations')

# Models for swagger documentation
token_check_model = api.model('TokenCheck', {
    'valid': fields.Boolean(description='Token validity status'),
    'user': fields.Raw(description='User information from token')
})

role_check_model = api.model('RoleCheck', {
    'hasRole': fields.Boolean(description='Whether user has the specified role'),
    'userRole': fields.String(description='User\'s actual role')
})

# Secret key for JWT (should match user service)
SECRET_KEY = "your-secret-key"


def extract_token(request):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None
    try:
        return auth_header.split(" ")[1]
    except IndexError:
        return None


@ns.route('/verify')
class TokenVerification(Resource):
    @ns.doc('verify_token',
            responses={
                200: 'Token is valid',
                401: 'Token is invalid or missing'
            })
    @ns.marshal_with(token_check_model)
    def get(self):
        # Verify if a JWT token is valid
        token = extract_token(request)
        if not token:
            api.abort(401, "Token is missing")

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            return {
                'valid': True,
                'user': payload
            }
        except JWTError as e:
            api.abort(401, f"Invalid token: {str(e)}")


@ns.route('/check-role/<string:required_role>')
@ns.param('required_role', 'The role to check against (e.g., Admin, User)')
class RoleCheck(Resource):
    @ns.doc('check_role',
            responses={
                200: 'Role check completed',
                401: 'Token is invalid or missing'
            })
    @ns.marshal_with(role_check_model)
    def get(self, required_role):
        # Check if the user has a specific role
        token = extract_token(request)
        if not token:
            api.abort(401, "Token is missing")

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_role = payload.get('role', '')
            # Case-insensitive comparison
            has_role = user_role.lower() == required_role.lower()
            return {
                'hasRole': has_role,
                'userRole': user_role
            }
        except JWTError as e:
            api.abort(401, f"Invalid token: {str(e)}")

# Error handler


@api.errorhandler(Exception)
def handle_error(error):
    if hasattr(error, 'code') and hasattr(error, 'description'):
        return {'message': str(error.description)}, error.code
    return {'message': 'Internal server error'}, 500


if __name__ == '__main__':
    app.run(port=5003, debug=True)
