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

def create_user(email, password, full_name, role="Employee"):
    import uuid
    """Creates a new user (Admin only function)."""
    session = SessionLocal()
    try:
        # Handle Guest Optional Email
        if role == 'Guest' and not email:
            # Generate placeholder to satisfy DB unique constraint
            email = f"guest_{uuid.uuid4().hex[:8]}@local.placeholder"
        
        if not email:
            return False, "Email is required for Non-Guest users"
            
        existing = session.query(User).filter_by(email=email).first()
        if existing:
            return False, "User already exists"
        
        # Hash password
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        new_user = User(
            email=email,
            password_hash=hashed,
            full_name=full_name,
            role=role,
            avatar_url=f"https://ui-avatars.com/api/?name={full_name}"
        )
        session.add(new_user)
        session.commit()
        return True, "User created successfully"
    except Exception as e:
        return False, str(e)
    finally:
        session.close()

def login_user(email, password):
    """Authenticates user and issues JWT."""
    session = SessionLocal()
    try:
        user = session.query(User).filter_by(email=email).first()
        if not user or not user.password_hash:
            return False, "Invalid credentials"
        
        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            # Generate Token
            access_token = create_access_token(
                data={"sub": user.email, "role": user.role, "user_id": user.id, "name": user.full_name}
            )
            set_session(user, access_token)
            return True, "Login successful"
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
    keys = ['jwt_token', 'user_id', 'user_email', 'user_name', 'user_role', 'user_upload_dir', 'selected_project_id', 'current_df', 'selected_severity']
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
    """Updates password for a user."""
    session = SessionLocal()
    try:
        user = session.query(User).get(user_id)
        if user:
            hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user.password_hash = hashed
            session.commit()
            return True, "Password updated successfully"
        return False, "User not found"
    except Exception as e:
        return False, str(e)
    finally:
        session.close()
