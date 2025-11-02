# SecureBudget Backend

Flask API for budget tracking app with security features.

## Quick Start

bash
cd backend

# Install
uv init
uv add flask flask-sqlalchemy flask-cors bcrypt pyjwt cryptography psycopg2-binary python-dotenv
uv sync

# Run
python app.py


## Setup

1. Create .env file:
env
DATABASE_URL=sqlite:///local_dev.db
SECRET_KEY=your-secret-key
DEBUG=True


2. Run the app - starts on http://localhost:5000

## API Endpoints

- POST /api/register - Create account
- POST /api/login - Login user  
- GET /api/transactions - Get transactions (auth required)
- POST /api/transactions - Add transaction (auth required)
- GET /health - Health check

## Security Features

- Password hashing with bcrypt
- JWT token authentication
- SQL injection prevention
- Input validation
- CORS enabled
- Error handling
