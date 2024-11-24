import json
import os
from functools import wraps

from flask import Flask, request
from flask_restx import Api, Resource, fields
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

api = Api(app, version='1.0', title='Destination Service API',
          description='A simple Destination Service API',
          authorizations=authorizations)

ns = api.namespace('api', description='Destination operations')

# Models for swagger documentation
destination_model = api.model('Destination', {
    'id': fields.Integer(required=True,  description='Destination ID'),
    'name': fields.String(required=True, description='Destination name'),
    'description': fields.String(required=True, description='Destination description'),
    'location': fields.String(required=True, description='Location name')
})

# Secret key for JWT (should match user service)
SECRET_KEY = "your-secret-key"


def load_destinations():
    if not os.path.exists('data/destinations.json'):
        os.makedirs('data', exist_ok=True)
        with open('data/destinations.json', 'w') as f:
            json.dump([], f)
    with open('data/destinations.json', 'r') as f:
        return json.load(f)


def save_destinations(destinations):
    with open('data/destinations.json', 'w') as f:
        json.dump(destinations, f, indent=4)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            api.abort(401, "Token is missing")

        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user = payload
            return f(*args, **kwargs)
        except Exception as e:
            api.abort(401, "Invalid token")

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            api.abort(401, "Token is missing")

        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            if payload.get('role') != 'Admin':
                api.abort(403, "Admin access required")
            return f(*args, **kwargs)
        except jwt.JWTError:
            api.abort(401, "Invalid token")
    return decorated


@ns.route('/destinations')
class DestinationList(Resource):
    @ns.doc('list_destinations', security=None)  # Remove security requirement
    @ns.marshal_list_with(destination_model)
    def get(self):
        """List all destinations (Public access)"""
        return load_destinations()

    # POST new destination by admin

    @ns.doc('create_destination', security='Bearer Auth')
    @ns.expect(api.model('CreateDestination', {
        'name': fields.String(required=True, description='Destination name'),
        'description': fields.String(required=True, description='Destination description'),
        'location': fields.String(required=True, description='Location name')
    }))
    @ns.marshal_with(destination_model, code=201)
    @ns.response(201, 'Destination created')
    @ns.response(401, 'Unauthorized')
    @ns.response(403, 'Admin access required')
    def post(self):
        """Create a new destination (Admin only)"""
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            api.abort(401, "Token is missing")

        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            if payload.get('role') != 'Admin':
                api.abort(403, "Admin access required")
        except jwt.JWTError:
            api.abort(401, "Invalid token")

        data = request.json
        destinations = load_destinations()

        # Generate new unique ID
        new_id = 1
        if destinations:
            new_id = max(dest['id'] for dest in destinations) + 1

        new_destination = {
            'id': new_id,
            'name': data['name'],
            'description': data['description'],
            'location': data['location']
        }

        destinations.append(new_destination)
        save_destinations(destinations)

        return new_destination, 201


@ns.route('/destinations/<int:id>')
@ns.param('id', 'The destination identifier')
class Destination(Resource):
    @ns.doc('delete_destination', security='Bearer Auth')
    @ns.response(204, 'Destination deleted')
    @ns.response(404, 'Destination not found')
    @ns.response(401, 'Unauthorized')
    @ns.response(403, 'Admin access required')
    def delete(self, id):
        """Delete a destination (Admin only)"""
        # First check admin authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            api.abort(401, "Token is missing")

        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            if payload.get('role') != 'Admin':
                api.abort(403, "Admin access required")
        except jwt.JWTError:
            api.abort(401, "Invalid token")

        # After authorization check, proceed with deletion
        destinations = load_destinations()
        destination = next(
            (dest for dest in destinations if dest['id'] == id), None)

        if not destination:
            api.abort(404, "Destination not found")

        destinations = [dest for dest in destinations if dest['id'] != id]
        save_destinations(destinations)

        return '', 204

# Add error handlers


@api.errorhandler(Exception)
def handle_error(error):
    if hasattr(error, 'code') and hasattr(error, 'description'):
        return {'message': str(error.description)}, error.code
    return {'message': 'Internal server error'}, 500


if __name__ == '__main__':
    app.run(port=5002, debug=True)
