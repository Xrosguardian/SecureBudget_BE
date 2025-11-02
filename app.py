from flask import Flask, jsonify, request
from flask_cors import CORS
from models import db, User, Transaction, AuditLog, SecurityTest
from auth import token_required, log_audit
from datetime import datetime, timedelta, timezone
import os
import logging
import re
from dotenv import load_dotenv  # Add this import
from sqlalchemy import text

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    CORS(app)
    
    # Configuration - get from environment variables
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Get database URL from environment
    database_url = os.environ.get('DATABASE_URL')
    
    if not database_url:
        logger.error("❌ DATABASE_URL environment variable is not set!")
        # Fallback to SQLite for testing
        database_url = 'sqlite:///test.db'
        logger.info("📁 Using SQLite fallback database")
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    logger.info(f"🔗 Database URL: {database_url[:50]}...")  # Log first 50 chars
    
    # Initialize extensions
    db.init_app(app)
    
    # Password validation
    def validate_password(password):
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r"\d", password):
            return False, "Password must contain at least one digit"
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character"
        return True, "Password is strong"
    
    # Initialize database tables
    with app.app_context():
        try:
            db.create_all()
            logger.info("✅ Database tables created successfully!")
            
            # Check if tables exist (updated for SQLAlchemy 2.0+)
            try:
                # Modern SQLAlchemy approach
                inspector = db.inspect(db.engine)
                tables = inspector.get_table_names()
                logger.info(f"📊 Available tables: {tables}")
            except Exception as inspect_error:
                logger.warning(f"Could not inspect tables: {inspect_error}")
            
        except Exception as e:
            logger.error(f"❌ Failed to create tables: {e}")
    
    # ===== AUTHENTICATION ROUTES =====
    @app.route('/api/register', methods=['POST'])
    def register():
        try:
            data = request.get_json()
            
            # Input validation
            if not data or not all(k in data for k in ['email', 'password', 'first_name', 'last_name']):
                return jsonify({'error': 'Missing required fields'}), 400
            
            # Email validation
            if not re.match(r'^[^@]+@[^@]+\.[^@]+$', data['email']):
                return jsonify({'error': 'Invalid email format'}), 400
            
            # Password strength validation
            is_valid, msg = validate_password(data['password'])
            if not is_valid:
                return jsonify({'error': msg}), 400
            
            # Check if user already exists
            if User.query.filter_by(email=data['email']).first():
                return jsonify({'error': 'Email already registered'}), 409
            
            # Create user
            user = User(
                email=data['email'],
                first_name=data['first_name'],
                last_name=data['last_name']
            )
            user.set_password(data['password'])
            
            db.session.add(user)
            db.session.commit()
            
            # Log the registration
            log_audit('register', user.id, f"User registered: {data['email']}")
            
            return jsonify({
                'message': 'User registered successfully',
                'user': user.to_dict(),
                'token': user.generate_token()
            }), 201
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    @app.route('/api/login', methods=['POST'])
    def login():
        try:
            data = request.get_json()
            
            if not data or not all(k in data for k in ['email', 'password']):
                return jsonify({'error': 'Email and password required'}), 400
            
            user = User.query.filter_by(email=data['email']).first()
            
            # Check if user exists and account is not locked
            if user and user.locked_until and user.locked_until > datetime.utcnow():
                return jsonify({'error': 'Account temporarily locked. Try again later.'}), 423
            
            # Check credentials
            if not user or not user.check_password(data['password']):
                if user:
                    user.login_attempts += 1
                    if user.login_attempts >= 5:
                        user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    db.session.commit()
                
                log_audit('login_failed', user.id if user else None, f"Failed login attempt for: {data['email']}")
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Reset login attempts on successful login
            user.login_attempts = 0
            user.locked_until = None
            db.session.commit()
            
            # Log successful login
            log_audit('login_success', user.id, f"User logged in: {data['email']}")
            
            return jsonify({
                'message': 'Login successful',
                'user': user.to_dict(),
                'token': user.generate_token()
            }), 200
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    # ===== PROTECTED ROUTES =====
    @app.route('/api/profile', methods=['GET'])
    @token_required
    def get_profile(current_user):
        return jsonify({'user': current_user.to_dict()})
    
    @app.route('/api/transactions', methods=['GET'])
    @token_required
    def get_transactions(current_user):
        transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.transaction_date.desc()).all()
        return jsonify({
            'transactions': [t.to_dict() for t in transactions]
        })
    
    @app.route('/api/transactions', methods=['POST'])
    @token_required
    def create_transaction(current_user):
        try:
            data = request.get_json()
            
            # Input validation
            if not data or not all(k in data for k in ['amount', 'transaction_type', 'category']):
                return jsonify({'error': 'Missing required fields'}), 400
            
            if data['transaction_type'] not in ['income', 'expense']:
                return jsonify({'error': 'Transaction type must be income or expense'}), 400
            
            # Validate amount is positive number
            try:
                amount = float(data['amount'])
                if amount <= 0:
                    return jsonify({'error': 'Amount must be positive'}), 400
            except ValueError:
                return jsonify({'error': 'Invalid amount format'}), 400
            
            # Create transaction
            transaction = Transaction(
                user_id=current_user.id,
                amount=amount,
                transaction_type=data['transaction_type'],
                category=data['category'],
                description=data.get('description', ''),
                transaction_date=datetime.utcnow()
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            log_audit('create_transaction', current_user.id, f"Created {data['transaction_type']}: ${data['amount']}")
            
            return jsonify({
                'message': 'Transaction created successfully',
                'transaction': transaction.to_dict()
            }), 201
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Transaction creation error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    # ===== DATABASE INFO ROUTE =====
    @app.route('/api/db-info')
    def db_info():
        try:
            # Get table counts
            user_count = User.query.count()
            transaction_count = Transaction.query.count()
            audit_count = AuditLog.query.count()
            
            # Get database info
            result = db.session.execute('SELECT version()')
            db_version = result.scalar()
            
            return jsonify({
                'database_version': db_version,
                'table_counts': {
                    'users': user_count,
                    'transactions': transaction_count,
                    'audit_logs': audit_count
                },
                'tables_created': True
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # ===== HEALTH CHECK ROUTES =====
    @app.route('/')
    def home():
        return jsonify({
            "message": "SecureBudget API is running!",
            "status": "success",
            "version": "1.0.0",
            "timestamp": datetime.utcnow().isoformat()
        })
    
    @app.route('/api/health')
    def health_check():
        try:
            # Fix: Use text() for raw SQL in SQLAlchemy 2.0+
            db.session.execute(text('SELECT 1'))
            db_status = "connected"
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            db_status = "disconnected"
        
        return jsonify({
            "status": "healthy", 
            "database": db_status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)