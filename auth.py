import streamlit as st
import bcrypt
from database import SessionLocal, User, UserRole, init_db
import os

# Initialize DB if not exists (called here to ensure safe start)
init_db()

def check_session():
    """Verifies if a user is logged in."""
    return 'user_id' in st.session_state and st.session_state['user_id'] is not None

def register_user(email, password, full_name, role="Employee"):
    """Registers a new user with hashed password."""
    session = SessionLocal()
    try:
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
        return True, "Registered successfully"
    except Exception as e:
        return False, str(e)
    finally:
        session.close()

def login_user(email, password):
    """Authenticates user via Email/Password."""
    session = SessionLocal()
    try:
        user = session.query(User).filter_by(email=email).first()
        if not user or not user.password_hash:
            return False, "Invalid credentials"
        
        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            set_session(user)
            return True, "Login successful"
        return False, "Invalid credentials"
    finally:
        session.close()

def set_session(user):
    """Sets session state variables."""
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
    keys = ['user_id', 'user_email', 'user_name', 'user_role', 'user_upload_dir']
    for key in keys:
        if key in st.session_state:
            del st.session_state[key]
