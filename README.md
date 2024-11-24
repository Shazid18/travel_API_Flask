# Travel API with Microservices

This project is a Python Flask-based microservices application for managing user accounts, destinations, and authentication. The application consists of three microservices:

1. **User Service**
2. **Destination Service**
3. **Auth Service**

Each microservice provides specific functionality, and they communicate with each other to deliver a complete travel management solution.

## Services Overview

### 1. User Service (Port: 5001)
Handles user authentication and profile management.

#### Endpoints:
- `POST /api/register` - Register new user
  - Requires: name, email, password, role
  - Validations:
    - Email must contain '@' and '.'
    - Password must be at least 8 characters
    - Email must not be already registered
  - Roles available: "Admin" or "User"

- `POST /api/login` - User authentication
  - Requires: email, password
  - Returns: JWT token

- `GET /api/profile` - Get current user's profile
  - Requires: Bearer token
  - Returns: User's profile information

- `GET /api/users_profile` - Get all users' profiles
  - Admin access only
  - Requires: Admin Bearer token
  - Returns: List of all users' profiles

### 2. Destination Service (Port: 5002)
Manages travel destinations.

#### Endpoints:
- `GET /api/destinations` - List all destinations
  - Public access
  - No authentication required

- `POST /api/destinations` - Create new destination
  - Admin access only
  - Requires: Admin Bearer token
  - Auto-generates unique ID
  - Required fields: name, description, location

- `DELETE /api/destinations/{id}` - Delete a destination
  - Admin access only
  - Requires: Admin Bearer token

### 3. Auth Service (Port: 5003)
Provides authentication and authorization functionalities.

#### Endpoints:
- `GET /api/auth/check-role/{required_role}` - Check if the user has the required role
  - Requires: Bearer token, role (e.g., Admin, User)
  - Returns: true or false with the orginal role

- `POST /api/auth/verify` - Verify the validity of the auth token
  - Requires: Bearer token
  - Returns: validity with user inforamtion


## Project Structure
#
#
```
travel-API
├── auth_service
│   ├── tests
│   │   ├── init.py
│   │   ├── test_auth_service.py
│   ├── app.py
├── destination_service
│   ├── data
│   │   ├── destinations.json
│   ├── tests
│   │   ├── init.py
│   │   ├── test_destination_service.py
│   ├── app.py
├── user_service
│   ├── data
│   │   ├── users.json
│   ├── tests
│   │   ├── init.py
│   │   ├── test_user_service.py
│   ├── app.py
├── .gitignore
├── requirements.txt
```


## Technical Details

### Architecture
- Microservices architecture with three independent services
- RESTful API design principles
- Swagger/OpenAPI specification for API documentation
- WSGI server using Flask's built-in development server
- ProxyFix middleware for handling proxy headers

### Authentication
- Uses JWT (JSON Web Tokens)
- Token must be included in Authorization header
- Format: `Bearer <token>`

### Data Storage
- User data: `data/users.json`
- Destination data: `data/destinations.json`

### Data model
- User Model 
     ```
    "name": "string",
    "email": "string",
    "password": "string (hashed)",
    "role": "string (Admin/User)"
    ```
- Destination Model
     ```
    "id": "integer (auto-generated)",
    "name": "string",
    "description": "string",
    "location": "string"
    ```

### Error Handling

The API returns appropriate **HTTP status codes** to indicate the result of each request:

- **200**: Success  
  The request was successful, and the response contains the expected data.

- **201**: Created successfully  
  The request was successful, and a new resource has been created.

- **400**: Bad request/validation errors  
  The request is malformed or invalid, such as missing required fields or incorrect data formats.

- **401**: Unauthorized  
  The user is not authenticated or the authentication token is missing or invalid.

- **403**: Forbidden  
  The user is authenticated but does not have sufficient permissions to access the resource.

- **404**: Not found  
  The requested resource could not be found.

- **500**: Server error  
  An internal server error occurred while processing the request.


### Security Considerations

The API includes several security measures to protect user data and ensure safe operation:

- **Password hashing**:  
  User passwords are hashed using the **pbkdf2_sha256** algorithm before being stored in the database to ensure secure password storage.

- **JWT Authentication**:  
  All API endpoints are protected with **JWT (JSON Web Token)** authentication to verify the identity of users and ensure secure access.

- **Role-based access control (RBAC)**:  
  Access to certain API resources is restricted based on user roles (e.g., Admin or User). This ensures that users only have access to resources and actions they are authorized to perform.

- **Input validation**:  
  Email and password inputs are validated to ensure they meet the required format, helping to prevent invalid or malicious data from being processed by the system.

## Requirements

- Python 3
- Flask
- pytest (for testing)

All project dependencies are listed in the `requirements.txt` file.

## Installation and Setup

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/Shazid18/travel_API_Flask.git
   cd travel_API_Flask
   ```
2. **Create a Virtual Environment**
    ```bash
   python -m venv venv
    source venv/bin/activate  # For Linux/macOS
    venv\Scripts\activate     # For Windows
   ```
3. **Install Dependencies**
    ```bash
   pip install -r requirements.txt
   ```
4. **Run Microservices**
    Each microservice runs independently. Navigate to the respective service directory and start the service:
    ```bash
    cd user_service
    python app.py
   ```
5. **Run Tests**
    To execute tests for any service, navigate to the respective service directory and run the following command:
    ```bash
    cd user_service
    pytest --cov=app --cov-report=term-missing tests/
   ```
6. **Repeate Step 4 and Step 5 to Run and Tests the other microservices with their respective service directory**
7. **Project will Run at:**
    - User Service: http://127.0.0.1:5001
    - Destination Service: http://127.0.0.1:5002
    - Auth Service: http://127.0.0.1:5003


## Testing Endpoints
Each service has its own set of API endpoints as described above. You can test them using OpenAPI/Swagger UI.

## Example Request for User Service

### 1. **Register New User**
**POST** `/api/register`

- **Description**: Register a new user by providing necessary details such as name, email, password( minimum length 8 ) and role.

- **Request Body**:
  ```
  {
    "name": "John Doe",
    "email": "user@example.com",
    "password": "your_password",
    "role": User
  }
  ```
- **Response Example**:
    ```
    {
      "User registered successfully"
    }
    ```


### 2. **Login**
**POST** `/api/login`

- **Description**: Login using email and password.
- **Request Body**:
  ```
  {
    "email": "user@example.com",
    "password": "your_password"
  }
  ```
- **Response Example**:
    ```
    {
      "auth_token": "your_jwt_token"
    }
    ```

### 3. **Get User Profile**
**GET** `/api/profile`

- **Description**: Get the profile of the logged-in user.
- **Headers**:
  - `Authorization: Bearer {your_jwt_token}`

- **Response Example**:
  ```
  {
    "name": "John Doe",
    "email": "user@example.com",
    "role": "User"
  }
  ```

## Example Request for Destination Service

### 1. **Add Destination** (Admin Only)
**POST** `/api/destinations`

- **Description**: Add a new destination. This endpoint is accessible only to admins.

- **Headers**:
  - `Authorization: Bearer {admin_jwt_token}`

- **Request Body**:
  ```
  {
    "name": "Paris",
    "description": "A beautiful city.",
    "location": "France"
  }
  ```


### 2. **Get All Destinations**
**GET** `/api/destinations`

- **Description**: Get the list of all available destinations. No authentication is required to access this endpoint.

- **Response Example**:
  ```
  [
    {
      "id": 1,
      "name": "Paris",
      "description": "A beautiful city known for its art, fashion, and culture.",
      "location": "France"
    },
    {
      "id": 2,
      "name": "New York",
      "description": "The city that never sleeps, known for its skyline and diverse culture.",
      "location": "USA"
    }
  ]
  ```
  
## Example Request for Auth Service

### 1. **Verify Token**
**GET** `/api/auth/verify`

- **Description**: Verify if the provided JWT token is valid.

- **Headers**:
  - `Authorization: Bearer {your_jwt_token}`

- **Response Example (Valid Token)**:
  ```
  {
    "valid": true,
    "user": {
    "email": "user@example.com",
    "role": "User"
    }
  }
  ```
- **Response Example (Invalid  Token)**:
  ```
  {
    "valid": false,
    "message": "Token is invalid"
  }
  ```
 
## Conclusion

This project demonstrates a simple **microservice architecture** using **Flask**, with **authentication** and **role-based access control**. Each service is **self-contained**, with its own API endpoints and **database** (stored as JSON files). The architecture allows for easy scaling and extension of the system.

### Key Features:
- **Microservice-based architecture**: Each component or service is independent and interacts through well-defined APIs.
- **Authentication and Authorization**: Role-based access control ensures that different users (Admin/User) have appropriate permissions.
- **Scalability and Extensibility**: The system can be easily scaled by adding more services or enhancing existing ones, making it adaptable to future requirements.

This approach offers flexibility, modularity, and the potential for rapid development and future expansion.