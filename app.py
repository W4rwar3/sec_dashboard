import streamlit as st
import pandas as pd
import plotly.express as px
from sqlalchemy.orm import Session
from database import engine, SessionLocal, init_db, Project, Vulnerability, User, Team, ProjectAccess, UserRole
from parsers import parse_file
from auth import check_session, login_user, register_user, logout_user, set_session
import datetime
import os

# --- Configuration ---
st.set_page_config(
    page_title="VAPT Analytics Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize DB (Safety check)
init_db()

# --- Theme & Visuals ---
if 'theme' not in st.session_state:
    st.session_state['theme'] = 'Light'

def toggle_theme():
    st.session_state['theme'] = 'Light' if st.session_state['theme'] == 'Dark' else 'Dark'

def get_plotly_template():
    return "plotly_dark" if st.session_state['theme'] == 'Dark' else "plotly_white"

def apply_custom_css():
    if st.session_state['theme'] == 'Dark':
        st.markdown("""
        <style>
        .stApp { background-color: #0e1117; color: white; }
        [data-testid="stSidebar"] { background-color: #262730; color: white; }
        div.stButton > button { background-color: #FF4B4B; color: white; border-radius: 5px; }
        </style>
        """, unsafe_allow_html=True)
    
    # Custom CSS for KPI Cards (Buttons) and Alignment
    st.markdown("""
    <style>
    /* KPI Button Styling */
    div.stButton > button.kpi-card {
        width: 100%;
        height: 100px;
        border: none;
        color: white;
        font-weight: bold;
        font-size: 1.2rem;
        transition: all 0.3s ease;
    }
    div.stButton > button.kpi-card:hover {
        transform: scale(1.02);
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    
    /* General Alignment Helpers */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    </style>
    """, unsafe_allow_html=True)

apply_custom_css()

# --- Sidebar ---
st.sidebar.title("VAPT Dashboard 🛡️")
st.sidebar.button("Toggle Theme 🌓", on_click=toggle_theme)

# --- Authentication Flow ---
if not check_session():
    st.title("🔒 Login to VAPT Dashboard")
    
    auth_mode = st.tabs(["Login", "Register", "Google Auth (Setup)"])
    
    with auth_mode[0]:
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            success, msg = login_user(email, password)
            if success:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)

    with auth_mode[1]:
        r_name = st.text_input("Full Name", key="reg_name")
        r_email = st.text_input("Email", key="reg_email")
        r_pass = st.text_input("Password", type="password", key="reg_pass")
        if st.button("Register"):
            success, msg = register_user(r_email, r_pass, r_name)
            if success:
                st.success("Registration successful! Please Log In.")
            else:
                st.error(msg)
    
    with auth_mode[2]:
        st.info("To enable Google Login, configure `client_secret.json` in the root directory.")
        # Future: Add file uploader for client_secret.json here

    st.stop()

# --- Authenticated View ---
user_role = st.session_state.get('user_role')
user_id = st.session_state.get('user_id')
st.sidebar.success(f"User: {st.session_state['user_name']} ({user_role})")

if st.sidebar.button("Logout"):
    logout_user()
    st.rerun()

# --- Navigation ---
page = st.sidebar.radio("Navigate", ["Dashboard", "Team Management"] if user_role in ['Admin', 'Manager'] else ["Dashboard"])

if page == "Team Management":
    st.header("👥 Team & User Management")
    session = SessionLocal()
    
    # 1. Create Team
    st.subheader("Create New Group/Team")
    with st.form("create_team"):
        team_name = st.text_input("Team Name")
        submitted = st.form_submit_button("Create Team")
        if submitted and team_name:
            new_team = Team(name=team_name, manager_id=user_id)
            session.add(new_team)
            session.commit()
            st.success(f"Team '{team_name}' Created!")
            st.rerun()

    # 2. Assign Members
    st.subheader("Assign Employees to Team")
    teams = session.query(Team).filter_by(manager_id=user_id).all() if user_role == "Manager" else session.query(Team).all()
    employees = session.query(User).filter(User.role == 'Employee').all()
    
    if teams and employees:
        c1, c2 = st.columns(2)
        with c1:
            team_map = {t.id: t.name for t in teams}
            tid = st.selectbox("Select Team", options=list(team_map.keys()), format_func=lambda x: team_map[x])
        with c2:
            emp_map = {e.id: f"{e.full_name} ({e.email})" for e in employees}
            eid = st.selectbox("Select Employee", options=list(emp_map.keys()), format_func=lambda x: emp_map[x])
        
        if st.button("Assign to Team"):
           emp = session.query(User).get(eid)
           emp.team_id = tid
           session.commit()
           st.success(f"Assigned to {team_map[tid]}")
           st.rerun()
    elif not teams:
        st.info("Create a team first.")
    
    # 3. View Teams
    st.divider()
    st.subheader("Existing Teams")
    all_teams = session.query(Team).all()
    for t in all_teams:
        with st.expander(f"Team: {t.name}", expanded=True):
             members = [u.full_name for u in t.members]
             st.write(f"Members: {', '.join(members) if members else 'None'}")

    session.close()

elif page == "Dashboard":
    session = SessionLocal()
    
    # 1. Load Project (Isolated)
    # Check for direct ownership OR Team Access
    projects = session.query(Project).filter(Project.owner_id == user_id).all()
   
    project_options = {p.id: p.project_name for p in projects}
    selected_project_id = st.sidebar.selectbox("Load Project", options=[None] + list(project_options.keys()), format_func=lambda x: project_options[x] if x else "Select...")
    
    # 2. Main Header
    c1, c2 = st.columns([3, 1])
    with c1: st.title("VAPT Analytics Dashboard")
    with c2:
        if st.button("Save Analysis 💾"):
            if 'current_df' in st.session_state and not st.session_state['current_df'].empty:
                new_project = Project(
                    project_name=f"Scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}",
                    total_vulns=len(st.session_state['current_df']),
                    owner_id=user_id
                )
                session.add(new_project)
                session.commit()
                # Bulk insert
                for _, row in st.session_state['current_df'].iterrows():
                    session.add(Vulnerability(
                        project_id=new_project.id,
                        severity=row['Severity'],
                        vuln_name=row['Name'],
                        description=row['Description'],
                        owasp_category=row['Category'],
                        file_location=str(row['File_Location'])
                    ))
                session.commit()
                st.success(f"Saved Project: {new_project.project_name}")
                st.rerun()
            else:
                st.error("No analysis to save.")

    # 3. File Upload (Isolated Storage)
    uploaded_file = st.file_uploader("Upload Report (Nessus/Burp/ZAP/Code/PDF/PPT/Word)", type=['xml', 'json', 'nessus', 'csv', 'xlsx', 'py', 'js', 'txt', 'pdf', 'ppt', 'pptx', 'docx', 'doc'])
    
    df = pd.DataFrame()
    
    if selected_project_id:
        vulns = session.query(Vulnerability).filter(Vulnerability.project_id == selected_project_id).all()
        df = pd.DataFrame([{
            'Severity': v.severity, 'Name': v.vuln_name, 'Description': v.description,
            'Category': v.owasp_category, 'File_Location': v.file_location
        } for v in vulns])
        st.info(f"Loaded: {project_options[selected_project_id]}")
        
    elif uploaded_file:
        # Save file to User Dir
        user_dir = st.session_state.get('user_upload_dir', 'uploads/temp')
        file_path = os.path.join(user_dir, uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Parse
        df = parse_file(uploaded_file)
        st.session_state['current_df'] = df
        st.success(f"File scanned and saved to: {file_path}")

    session.close()

    # 4. Visuals
    if not df.empty:
        try:
            # --- Pre-process ---
            # 1. Ensure Columns Exist
            required_cols = ['Severity', 'Name', 'Category', 'File_Location', 'Description']
            for col in required_cols:
                if col not in df.columns:
                    df[col] = "Unknown"
            
            # 2. Handle Missing Values
            df.fillna("Unknown", inplace=True)

            # 3. Standardize Severity
            # Map 'Info' to 'Informational' for consistency with requirements
            df.loc[df['Severity'].astype(str).str.title().str.strip() == 'Info', 'Severity'] = 'Informational'
            
            severity_order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
            
            # Normalize casing and strip whitespace
            df['Severity'] = df['Severity'].astype(str).str.title().str.strip()
            
            # Map unknown severities to 'Informational'
            df.loc[~df['Severity'].isin(severity_order), 'Severity'] = 'Informational'

            df['Severity'] = pd.Categorical(df['Severity'], categories=severity_order, ordered=True)
            df.sort_values('Severity', inplace=True)
            
            REQUIRED_COLORS = {
                'Critical': '#8B0000',      # Dark Red
                'High': '#FF0000',          # Red
                'Medium': '#FFA500',        # Orange
                'Low': '#FFFF00',           # Yellow
                'Informational': '#ADD8E6'  # Light Blue/Gray (Using LightBlue for visibility)
            }
            
            # --- KPI Interactive State ---
            if 'selected_severity' not in st.session_state:
                st.session_state['selected_severity'] = 'Total'

            def set_severity(sev):
                st.session_state['selected_severity'] = sev

            # --- Row 1: KPI Cards (Interactive) ---
            # Requirement: Total, Critical, High, Medium, Low, Informational (6 cols)
            
            # Calculate counts
            total_count = len(df)
            crit_count = len(df[df['Severity'] == 'Critical'])
            high_count = len(df[df['Severity'] == 'High'])
            med_count = len(df[df['Severity'] == 'Medium'])
            low_count = len(df[df['Severity'] == 'Low'])
            info_count = len(df[df['Severity'] == 'Informational'])

            st.markdown("### Executive Summary")
            
            # Helper to create styled buttons (Streamlit buttons don't support direct style args easily, 
            # so we rely on key hacking or custom CSS overrides if possible, but standard buttons are safer for logic.
            # We will use columns and standard buttons, effectively acting as tabs).
            
            k1, k2, k3, k4, k5, k6 = st.columns(6, gap="small")
            
            # To style these buttons individually, simpler approach is standard buttons with coloring via emoji or text
            # ideally we'd inject CSS for specific IDs, but Streamlit generates dynamic IDs.
            # We will use st.metric as visual IF it was static, but user wants CLICK interaction.
            # We will use Buttons. 
            
            # Note: Custom coloring of specific buttons is tricky in pure Streamlit without complex CSS injection per button index.
            # We will rely on the "selected" state logic to filter. 
            # For the "Distinct Color" requirement, we might need to rely on the Charts coloring mostly, 
            # or try to inject styled HTML buttons that trigger streamlit callbacks (advanced).
            # For robustness, we will standard buttons but add emojis/indicators.
            
            with k1:
                if st.button(f"Total\n{total_count}", key="btn_total", use_container_width=True):
                    set_severity('Total')
            with k2:
                if st.button(f"Critical\n{crit_count}", key="btn_crit", use_container_width=True):
                    set_severity('Critical')
            with k3:
                if st.button(f"High\n{high_count}", key="btn_high", use_container_width=True):
                    set_severity('High')
            with k4:
                if st.button(f"Medium\n{med_count}", key="btn_med", use_container_width=True):
                    set_severity('Medium')
            with k5:
                if st.button(f"Low\n{low_count}", key="btn_low", use_container_width=True):
                    set_severity('Low')
            with k6:
                if st.button(f"Info\n{info_count}", key="btn_info", use_container_width=True):
                    set_severity('Informational')

            # Show current selection
            st.caption(f"Currently Showing: **{st.session_state['selected_severity']}** Findings")

            # --- Filter Data ---
            if st.session_state['selected_severity'] == 'Total':
                filtered_df = df
            else:
                filtered_df = df[df['Severity'] == st.session_state['selected_severity']]

            st.divider()
            
            if filtered_df.empty:
                st.info(f"No findings found for severity: {st.session_state['selected_severity']}")
            else:
                # --- Row 2: Charts ---
                r2_1, r2_2, r2_3 = st.columns(3)
                
                with r2_1:
                    st.subheader("Severity Distribution")
                    try:
                        # Pie chart only makes sense for Total, but if filtered, it shows 100% of that severity.
                        # User requirement: "Update charts to display data specific to selected severity"
                        # If 'Critical' is selected, this Pie will be 100% Critical.
                        fig_pie = px.pie(filtered_df, names='Severity', color='Severity', 
                                         color_discrete_map=REQUIRED_COLORS, hole=0.4, 
                                         template=get_plotly_template())
                        st.plotly_chart(fig_pie, use_container_width=True)
                    except Exception as e:
                        st.error(f"Chart Error: {e}")

                with r2_2:
                    st.subheader("Categories")
                    try:
                        cat_counts = filtered_df['Category'].value_counts().reset_index(name='Count')
                        if 'index' in cat_counts.columns: cat_counts.rename(columns={'index': 'Category'}, inplace=True) 
                        
                        # Fix color mapping for Categories if possible, or just use default. 
                        # Using 'Category' for color to keep it distinct
                        fig_bar = px.bar(cat_counts, x='Category', y='Count', 
                                         template=get_plotly_template(), color='Category')
                        st.plotly_chart(fig_bar, use_container_width=True)
                    except Exception as e:
                         st.error(f"Chart Error: {e}")

                with r2_3:
                    st.subheader("Top Risk Assets")
                    try:
                        loc_counts = filtered_df['File_Location'].value_counts().head(5).reset_index(name='Count')
                        if 'index' in loc_counts.columns: loc_counts.rename(columns={'index': 'File_Location'}, inplace=True)
                        
                        fig_area = px.area(loc_counts, x='File_Location', y='Count', 
                                           template=get_plotly_template())
                        st.plotly_chart(fig_area, use_container_width=True)
                    except Exception as e:
                         st.error(f"Chart Error: {e}")

                st.divider()
                st.subheader(f"Analysis Findings ({st.session_state['selected_severity']})")
                st.dataframe(filtered_df, use_container_width=True)
        
        except Exception as e:
            st.error(f"An error occurred while processing the visualization: {e}")
            st.write(df.head()) # Show data snippet for debugging logic

    else:
        st.info("Upload a file to begin VAPT Analysis.")
