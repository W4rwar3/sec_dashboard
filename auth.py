import streamlit as st
import bcrypt
import jwt
from datetime import datetime, timedelta
from database import SessionLocal, User, UserRole, init_db
import os

# Initialize DB if not exists
init_db()

# --- JWT Config ---
SECRET_KEY = "vapt-dashboard-secret-key-change-me" # In prod, use env var
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def create_access_token(data: dict):
    """Generates a JWT token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    """Decodes and validates a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def check_session():
    """Verifies if a valid JWT exists in session."""
    if 'jwt_token' not in st.session_state:
        return False
    
    payload = verify_token(st.session_state['jwt_token'])
    if payload:
        return True
    else:
        # Token invalid/expired
        logout_user()
        return False

import re

# Validation Patterns
REGEX_PATTERNS = {
    'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    'password': r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', # Min 8, 1 char, 1 num, 1 special
    'name': r'^[a-zA-Z0-9\s\-_]{3,50}$', # Alphanumeric, spaces, dash, underscore, 3-50 chars
    'generic_name': r'^[a-zA-Z0-9\s\-_]{3,50}$', # For Project/Team names
    'filename': r'^[a-zA-Z0-9\s\-_.]+$' # Allow dots for extensions
}

def validate_input(text, type_key):
    """Validates text against a regex pattern."""
    if not text: return False
    pattern = REGEX_PATTERNS.get(type_key)
    if pattern and re.match(pattern, text):
        return True
    return False

def create_user(email, password, full_name, role="Employee"):
    import uuid
    """Creates a new user (Admin only function)."""
    
    # 1. Validation
    if role != 'Guest': # Guest email is auto-generated or optional check logic below
        if not validate_input(email, 'email'):
            return False, "Invalid Email Format"
    
    if not validate_input(password, 'password'):
        return False, "Password too weak. Must be 8+ chars, include number and special char."
        
    if not validate_input(full_name, 'name'):
        return False, "Invalid Name (3-50 chars, alphanumeric)"

    session = SessionLocal()
    try:
        # Handle Guest Optional Email
        if role == 'Guest' and not email:
            # Generate placeholder to satisfy DB unique constraint
            email = f"guest_{uuid.uuid4().hex[:8]}@local.placeholder"
        
        if not email:
            return False, "Email is required for Non-Guest users"
            
        # 2. Uniqueness Check (Email & Name)
        existing_email = session.query(User).filter_by(email=email).first()
        if existing_email:
            return False, "User with this email already exists"

        existing_name = session.query(User).filter_by(full_name=full_name).first()
        if existing_name:
             return False, "User with this name already exists"
        
        # Hash password
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        new_user = User(
            email=email,
            password_hash=hashed,
            full_name=full_name,
            role=role,
            avatar_url=f"https://ui-avatars.com/api/?name={full_name}",
            must_change_password=(role != 'Guest') # Guest cannot change, others must
        )
        session.add(new_user)
        session.commit()
        return True, "User created successfully"
    except Exception as e:
        return False, str(e)
    finally:
        session.close()

def login_user(email, password):
    """Authenticates user and issues JWT. Handles Lockout & Failed Attempts."""
    session = SessionLocal()
    try:
        user = session.query(User).filter_by(email=email).first()
        
        # 1. Check if user exists
        if not user:
            # Generic error for security
            return False, "Invalid credentials"

        # 2. Check Lockout
        if user.lockout_until:
            if datetime.utcnow() < user.lockout_until:
                 remaining = int((user.lockout_until - datetime.utcnow()).total_seconds() / 60)
                 return False, f"Account temporarily locked. Try again in {remaining} minutes."
            else:
                 # Lockout expired, reset
                 user.lockout_until = None
                 user.failed_login_attempts = 0
                 session.commit()
                 
        # 3. Verify Password
        if user.password_hash and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            # SUCCESS
            user.failed_login_attempts = 0
            user.lockout_until = None
            session.commit()
            
            # Generate Token
            # Embed 'must_change_password' in token or rely on DB check in UI?
            # Better to check DB in UI flow, token just carries identity.
            # Check First Login Policy
            if user.must_change_password and user.role != 'Guest':
                return True, "Login successful. Password change required."
            
            # Generate Token & Set Session (Only if no password change needed)
            access_token = create_access_token(
                data={"sub": user.email, "role": user.role, "user_id": user.id, "name": user.full_name}
            )
            set_session(user, access_token)
                
            return True, "Login successful"
            
        else:
            # FAILURE
            user.failed_login_attempts += 1
            
            if user.failed_login_attempts >= 5:
                # Lockout for 15 minutes
                user.lockout_until = datetime.utcnow() + timedelta(minutes=15)
                session.commit()
                return False, "Account temporarily locked due to repeated failed attempts. Try again later."
            
            session.commit()
            return False, "Invalid credentials"
            
    finally:
        session.close()

def set_session(user, token):
    """Sets session state with JWT."""
    st.session_state['jwt_token'] = token
    st.session_state['user_id'] = user.id
    st.session_state['user_email'] = user.email
    st.session_state['user_name'] = user.full_name
    st.session_state['user_role'] = user.role
    
    # Create user upload directory
    user_dir = os.path.join("uploads", str(user.id))
    os.makedirs(user_dir, exist_ok=True)
    st.session_state['user_upload_dir'] = user_dir

def logout_user():
    """Clears session."""
    keys = ['jwt_token', 'user_id', 'user_email', 'user_name', 'user_role', 'user_upload_dir', 'selected_project_id', 'current_df', 'selected_severity', 'must_change_password_uid']
    for key in keys:
        if key in st.session_state:
            del st.session_state[key]

def delete_user(user_id):
    """Deletes a user by ID."""
    session = SessionLocal()
    try:
        user = session.query(User).get(user_id)
        if user:
            session.delete(user)
            session.commit()
            return True, "User deleted successfully"
        return False, "User not found"
    except Exception as e:
        return False, str(e)
    finally:
        session.close()

def update_password(user_id, new_password):
    """Updates password for a user. (Admin Reset or User Change)."""
    # Note: For strict 'Old Password' check, we'd need another arg. 
    # Current flow in app.py for Admin reset doesn't ask old pass.
    # For First Login flow, we just set new pass.
    
    session = SessionLocal()
    try:
        user = session.query(User).get(user_id)
        if user:
            # 1. Validate Strength (Double Check)
            if not validate_input(new_password, 'password'):
                 return False, "Password too weak. Min 8 chars, 1 Special, 1 Number."
            
            hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user.password_hash = hashed
            user.must_change_password = False # Reset flag
            user.failed_login_attempts = 0 # Reset any counters
            user.lockout_until = None
            session.commit()
            return True, "Password updated successfully"
        return False, "User not found"
    except Exception as e:
        return False, str(e)
    finally:
        session.close()
