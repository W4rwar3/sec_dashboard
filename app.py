import streamlit as st
import pandas as pd
import plotly.express as px
from sqlalchemy.orm import Session
from database import engine, SessionLocal, init_db, Project, Vulnerability, User, Team, ProjectAccess, UserRole
from parsers import parse_file
from auth import check_session, login_user, check_session, logout_user, set_session, create_user, delete_user, update_password
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

def mask_email(email):
    """Masks email for display."""
    if not email or '@' not in email: return email
    try:
        user, domain = email.split('@')
        if len(user) > 3:
            return f"{user[:3]}****@{domain}"
        return f"{user[:1]}****@{domain}"
    except:
        return email

def toggle_theme():
    st.session_state['theme'] = 'Light' if st.session_state['theme'] == 'Dark' else 'Dark'

def get_plotly_template():
    return "plotly_dark" if st.session_state['theme'] == 'Dark' else "plotly_white"

def apply_custom_css():
    theme = st.session_state['theme']
    
    # 1. Global Colours
    if theme == 'Dark':
        bg_color = '#0e1117'
        text_color = '#ffffff'
        card_bg = '#262730'
        sidebar_bg = '#262730'
        input_bg = '#1f2029'
        border_color = '#41444C'
        btn_bg = '#262730'
    else:
        bg_color = '#ffffff'
        text_color = '#31333F'
        card_bg = '#f0f2f6'
        sidebar_bg = '#f0f2f6'
        input_bg = '#ffffff'
        border_color = '#d6d6d8'
        btn_bg = '#ffffff'

    # 2. Main Theme CSS
    st.markdown(f"""
    <style>
    /* Main Layout */
    .stApp {{ background-color: {bg_color}; color: {text_color}; }}
    [data-testid="stSidebar"] {{ background-color: {sidebar_bg}; color: {text_color}; }}
    header[data-testid="stHeader"] {{ background-color: {bg_color}; }}
    
    /* Inputs & UI Elements (Force Dark/Light consistency) */
    .stTextInput > div > div > input {{ color: {text_color}; background-color: {input_bg}; }}
    .stSelectbox > div > div {{ color: {text_color}; background-color: {input_bg}; }}
    div[data-baseweb="select"] > div {{ background-color: {input_bg} !important; color: {text_color} !important; }}
    
    /* Buttons (Force Theme Consistency) */
    div.stButton > button, div.stDownloadButton > button {{
        background-color: {btn_bg};
        color: {text_color};
        border: 1px solid {border_color};
    }}
    
    /* Expanders */
    [data-testid="stExpander"] {{
        background-color: {card_bg};
        color: {text_color};
        border-radius: 5px;
    }}
    
    /* Tables & Dataframes */
    [data-testid="stDataFrame"] {{ background-color: {card_bg}; }}
    [data-testid="stTable"] {{ color: {text_color}; }}
    
    /* Sidebar Cleanup: Remove Radio Buttons, keep text */
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > label > div:first-child {{
        display: None;
    }}
    [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] {{
        gap: 1.5rem; /* Increase spacing between items */
    }}

    </style>
    """, unsafe_allow_html=True)
    
    # 3. KPI Cards Styling (Base)
    st.markdown("""
    <style>
    div.stButton > button {
        width: 100%;
        border: 1px solid rgba(128, 128, 128, 0.2);
        border-radius: 10px;
        transition: transform 0.2s;
    }
    div.stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
    </style>
    """, unsafe_allow_html=True)

def update_chart_layout(fig):
    theme = st.session_state['theme']
    if theme == 'Dark':
        fig.update_layout(
            paper_bgcolor='#262730', 
            plot_bgcolor='#262730',
            font={'color': '#ffffff'}
        )
    else:
        fig.update_layout(
            paper_bgcolor='#ffffff',
            plot_bgcolor='#ffffff',
            font={'color': '#31333F'}
        )
    return fig

apply_custom_css()

# --- Sidebar ---
st.sidebar.title("VAPT Dashboard 🛡️")
# Removed Top Theme Button

# --- Authentication Flow ---
if not check_session():
    st.title("🔒 Login to VAPT Dashboard")
    
    # only login, no registration for public
    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_pass")
    
    if st.button("Login"):
        success, msg = login_user(email, password)
        if success:
            st.success(msg)
            st.rerun()
        else:
            st.error(msg)
    
    st.info("Note: Public registration is disabled. Contact Administrator for access.")
    st.stop()

# --- Authenticated View ---
user_role = st.session_state.get('user_role')
user_id = st.session_state.get('user_id')
from reports import generate_csv, generate_pdf

# --- Sidebar Redesign ---
# 1. Profile Section
with st.sidebar:
    st.markdown("""
        <div style="text-align: center; padding: 10px;">
            <div style="font-size: 3rem;">👤</div>
            <h3 style="margin:0;">{}</h3>
            <p style="color: gray; font-size: 0.9rem;">{}</p>
    """.format(st.session_state.get('user_name', 'Guest'), st.session_state.get('user_role', 'Visitor')), unsafe_allow_html=True)
    
    # Show Team if Employee
    if st.session_state.get('user_role') == 'Employee':
        session = SessionLocal()
        user_db = session.query(User).get(user_id)
        if user_db and user_db.team:
             st.caption(f"{user_db.team.name}")
        session.close()
    
    # Removed Button here

# 2. Navigation
nav_options = ["Dashboard"]
if user_role == 'Admin':
    nav_options.append("User & Team Management")
elif user_role == 'Manager':
    nav_options.append("Team Management")

page = st.sidebar.radio("Navigate", nav_options, label_visibility="collapsed")

# 3. Footer (Logout & Theme)
st.sidebar.markdown("---")
c_foot1, c_foot2 = st.sidebar.columns([3, 1])
with c_foot1:
    if st.button("Logout 🚪", use_container_width=True):
        logout_user()
        st.rerun()
with c_foot2:
    if st.button("🌓", help="Toggle Theme", use_container_width=True):
        toggle_theme()
        st.rerun()

# --- Page Routing ---
# --- Page Routing ---
if page == "User & Team Management" or page == "Team Management":
    st.header("👥 Admin Panel: User & Team Management")
    session = SessionLocal()
    
    # Tabs for Admin actions
    if user_role == 'Admin':
        tabs = st.tabs(["User Management", "Create New User", "Project Access (Guests)", "Teams"])
    else:
        tabs = st.tabs(["Teams"]) # Managers only see Teams
    
    # Tab 0: User Management (List & Actions)
    if user_role == 'Admin':
        with tabs[0]:
            st.subheader("Manage Users")
            all_users = session.query(User).all()
            
            # Header
            h1, h2, h3, h4 = st.columns([2, 1, 2, 2])
            h1.markdown("**User**")
            h2.markdown("**Role**")
            h3.markdown("**Email**")
            h4.markdown("**Actions**")
            st.divider()
            
            for u in all_users:
                # Skip self
                if u.id == user_id: continue
                
                c1, c2, c3, c4 = st.columns([2, 1, 2, 2])
                c1.write(f"{u.full_name}")
                c2.caption(f"{u.role}")
                c3.write(f"{mask_email(u.email)}")
                
                with c4:
                    with st.expander("Manage"):
                        # Delete
                        if u.role in ['Employee', 'Manager', 'Guest']:
                             if st.button(f"Delete User", key=f"del_usr_{u.id}"):
                                 # Basic confirmation by UI design usually requires a state or double click, 
                                 # but for now a button is direct.
                                 success, msg = delete_user(u.id)
                                 if success: st.success(msg); st.rerun()
                                 else: st.error(msg)

                        # Secure Password Reset
                        with st.form(f"reset_pass_{u.id}"):
                            st.caption("Secure Password Change")
                            verify_email = st.text_input("Verify Email (Required)", key=f"v_email_{u.id}")
                            new_pass = st.text_input("New Password", type="password", key=f"n_pass_{u.id}")
                            
                            if st.form_submit_button("Update Password"):
                                if verify_email == u.email:
                                    success, msg = update_password(u.id, new_pass)
                                    if success: st.success(msg)
                                    else: st.error(msg)
                                else:
                                    st.error("Email verification failed! Action Blocked.")
                st.divider()

    # Tab 1: Create User (Admin Only)
    if user_role == 'Admin':
        with tabs[1]:
            st.subheader("Create New User")
            with st.form("create_user_form"):
                new_email = st.text_input("Email (Optional for Guest)")
                new_pass = st.text_input("Password", type="password")
                new_name = st.text_input("Full Name")
                new_role = st.selectbox("Role", ["Employee", "Guest", "Admin", "Manager"])
                
                if st.form_submit_button("Create User"):
                    if new_pass:
                        success, msg = create_user(new_email, new_pass, new_name, new_role)
                        if success: st.success(msg)
                        else: st.error(msg)
                    else:
                        st.warning("Password is required")

        # Tab 2: Guest Project Access (Admin Only)
        with tabs[1]:
            st.subheader("Assign Project Access to Guests")
            guests = session.query(User).filter(User.role == 'Guest').all()
            all_projects = session.query(Project).all()
            
            if guests and all_projects:
                c1, c2 = st.columns(2)
                with c1:
                    guest_map = {u.id: u.full_name for u in guests}
                    selected_guest_id = st.selectbox("Select Guest", options=list(guest_map.keys()), format_func=lambda x: guest_map[x])
                with c2:
                    proj_map = {p.id: p.project_name for p in all_projects}
                    selected_proj_id = st.selectbox("Select Project", options=list(proj_map.keys()), format_func=lambda x: proj_map[x])
                
                if st.button("Grant Access"):
                    # Check if exists
                    exists = session.query(ProjectAccess).filter_by(user_id=selected_guest_id, project_id=selected_proj_id).first()
                    if not exists:
                        pa = ProjectAccess(user_id=selected_guest_id, project_id=selected_proj_id)
                        session.add(pa)
                        session.commit()
                        st.success(f"Access granted for project '{proj_map[selected_proj_id]}'")
                    else:
                        st.info("Access already exists.")
            else:
                st.info("Need Guests and Projects to assign access.")

    # Tab 3: Teams (Shared Admin/Manager)
    # Re-using previous Team logic, putting it in the correct tab
    target_tab = tabs[2] if user_role == 'Admin' else tabs[0]
    with target_tab:
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
    
    # --- Logic: List vs Analytics ---
    # Check if we are in "Analytics Mode" (Project Loaded or File Uploaded)
    in_analytics_mode = False
    
    # 1. Check for Loaded Project ID
    if 'selected_project_id' in st.session_state:
        in_analytics_mode = True
        pid = st.session_state['selected_project_id']
        project = session.query(Project).get(pid)
        if project:
            vulns = session.query(Vulnerability).filter(Vulnerability.project_id == pid).all()
            df = pd.DataFrame([{
                'Severity': v.severity, 'Name': v.vuln_name, 'Description': v.description,
                'Category': v.owasp_category, 'File_Location': v.file_location
            } for v in vulns])
            project_name = project.project_name
            # If loaded from DB, ensure current_df is synced for consistent visuals
            st.session_state['current_df'] = df

    # 2. Check for File Upload (overrides project load if happened in this session context logic, 
    # but we usually reset selected_project_id on upload. 
    # Just checking 'current_df' is reliable if we stick to this flow).
    elif 'current_df' in st.session_state and not st.session_state['current_df'].empty:
        in_analytics_mode = True
        df = st.session_state['current_df']
        project_name = "Unsaved_Analysis" # Default until saved
    
    
    # --- VIEW: ANALYTICS ---
    if in_analytics_mode and not df.empty:
        # Back Button
        if st.button("← Back to Projects"):
            if 'selected_project_id' in st.session_state: del st.session_state['selected_project_id']
            if 'current_df' in st.session_state: del st.session_state['current_df']
            st.rerun()

        # Header
        c1, c2 = st.columns([3, 1])
        with c1: st.title(f"📊 {project_name}")
        with c2:
             # Save Snapshot logic (Only show if not saved or modified? For now keep simple)
             if 'selected_project_id' not in st.session_state: # Only if fresh upload
                 if st.button("Save to Projects 💾"):
                    new_project = Project(
                        project_name=f"Scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}",
                        total_vulns=len(df),
                        owner_id=user_id
                    )
                    session.add(new_project)
                    session.commit()
                    for _, row in df.iterrows():
                        session.add(Vulnerability(
                            project_id=new_project.id,
                            severity=row['Severity'],
                            vuln_name=row['Name'],
                            description=row['Description'],
                            owasp_category=row['Category'],
                            file_location=str(row['File_Location'])
                        ))
                    session.commit()
                    st.success("Project Saved!")
                    st.session_state['selected_project_id'] = new_project.id # Switch to loaded mode
                    st.rerun()

        # Visuals
        figures = {}
        try:
            # Pre-process
            required_cols = ['Severity', 'Name', 'Category', 'File_Location', 'Description']
            for col in required_cols:
                if col not in df.columns: df[col] = "Unknown"
            df.fillna("Unknown", inplace=True)

            # Standardize Severity
            df.loc[df['Severity'].astype(str).str.title().str.strip() == 'Info', 'Severity'] = 'Informational'
            severity_order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
            df['Severity'] = df['Severity'].astype(str).str.title().str.strip()
            df.loc[~df['Severity'].isin(severity_order), 'Severity'] = 'Informational'
            df['Severity'] = pd.Categorical(df['Severity'], categories=severity_order, ordered=True)
            df.sort_values('Severity', inplace=True)
            
            REQUIRED_COLORS = {'Critical': '#8B0000', 'High': '#FF0000', 'Medium': '#FFA500', 'Low': '#FFFF00', 'Informational': '#ADD8E6'}
            
            # KPI
            if 'selected_severity' not in st.session_state: st.session_state['selected_severity'] = 'Total'
            def set_severity(sev): st.session_state['selected_severity'] = sev

            total_count = len(df)
            crit_count = len(df[df['Severity'] == 'Critical'])
            high_count = len(df[df['Severity'] == 'High'])
            med_count = len(df[df['Severity'] == 'Medium'])
            low_count = len(df[df['Severity'] == 'Low'])
            info_count = len(df[df['Severity'] == 'Informational'])

            st.markdown("### Executive Summary")

            # --- KPI SUMMARY (6 Real Security Metrics) ---
            
            # 1. Calc Counts
            total_count = len(df)
            crit_count = len(df[df['Severity'] == 'Critical'])
            high_count = len(df[df['Severity'] == 'High'])
            med_count = len(df[df['Severity'] == 'Medium'])
            low_count = len(df[df['Severity'] == 'Low'])
            info_count = len(df[df['Severity'] == 'Informational'])

            # 2. Inject CSS with Unique IDs for Each Card
            # FIX: Scope styles ONLY to these specific IDs to avoid breaking other buttons
            st.markdown("""
            <style>
            /* Apply BOX Style ONLY to the KPI Buttons */
            div:has(#kpi-total) + div.stButton > button,
            div:has(#kpi-critical) + div.stButton > button,
            div:has(#kpi-high) + div.stButton > button,
            div:has(#kpi-medium) + div.stButton > button,
            div:has(#kpi-low) + div.stButton > button ,
            div:has(#kpi-info) + div.stButton > button {
                height: 100px;
                width: 100%;
                border: none;
                border-radius: 4px;
                color: white;
                font-family: 'Source Sans Pro', sans-serif;
                font-weight: 700;
                font-size: 20px;
                text-align: left;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: flex-start;
                padding-left: 20px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                transition: transform 0.2s;
            }
            
            div:has(#kpi-total) + div.stButton > button:hover,
            div:has(#kpi-critical) + div.stButton > button:hover,
            div:has(#kpi-high) + div.stButton > button:hover,
            div:has(#kpi-medium) + div.stButton > button:hover,
            div:has(#kpi-low) + div.stButton > button:hover,
            div:has(#kpi-info) + div.stButton > button:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 10px rgba(0,0,0,0.2);
                filter: brightness(110%);
                color: white !important;
            }

            /* --- UNIQUE COLOR RULES PER CARD --- */
            
            /* 1. TOTAL (Blue) */
            div:has(#kpi-total) + div.stButton > button {
                background: linear-gradient(135deg, #00c0ef 0%, #0097bc 100%) !important;
            }

            /* 2. CRITICAL (Dark Red - Solid) */
            div:has(#kpi-critical) + div.stButton > button {
                background: #8B0000 !important;
                background-color: #8B0000 !important;
                background-image: none !important;
                border: 1px solid #8B0000 !important;
            }
            div:has(#kpi-critical) + div.stButton > button:hover {
                background: #600000 !important; /* Even Darker on hover */
                background-color: #600000 !important;
                filter: none !important; /* Disable brightness boost */
                box-shadow: 0 6px 12px rgba(0,0,0,0.3) !important;
            }

            /* 3. HIGH (Orange) */
            div:has(#kpi-high) + div.stButton > button {
                background: linear-gradient(135deg, #f39c12 0%, #c87f0a 100%) !important;
            }

            /* 4. MEDIUM (Yellow) */
            div:has(#kpi-medium) + div.stButton > button {
                 background: linear-gradient(135deg, #ffc107 0%, #dba915 100%) !important;
                 color: #333 !important; /* Dark text for contrast on yellow */
            }

            /* 5. LOW (Green) */
            div:has(#kpi-low) + div.stButton > button {
                background: linear-gradient(135deg, #00a65a 0%, #008d4c 100%) !important;
            }

            /* 6. INFO (Teal) */
            div:has(#kpi-info) + div.stButton > button {
                background: linear-gradient(135deg, #39cccc 0%, #30bbbb 100%) !important;
            }
            </style>
            """, unsafe_allow_html=True)

            # ROW 1 columns
            r1_c1, r1_c2, r1_c3 = st.columns(3)
            with r1_c1:
                st.markdown('<span id="kpi-total"></span>', unsafe_allow_html=True)
                if st.button(f"Total\n{total_count}", key="btn_total", use_container_width=True):
                    set_severity('Total')
            with r1_c2:
                st.markdown('<span id="kpi-critical"></span>', unsafe_allow_html=True)
                if st.button(f"Critical\n{crit_count}", key="btn_crit", use_container_width=True):
                    set_severity('Critical')
            with r1_c3:
                st.markdown('<span id="kpi-high"></span>', unsafe_allow_html=True)
                if st.button(f"High\n{high_count}", key="btn_high", use_container_width=True):
                    set_severity('High')
            
            # ROW 2 columns
            r2_c1, r2_c2, r2_c3 = st.columns(3)
            with r2_c1:
                st.markdown('<span id="kpi-medium"></span>', unsafe_allow_html=True)
                if st.button(f"Medium\n{med_count}", key="btn_med", use_container_width=True):
                    set_severity('Medium')
            with r2_c2:
                st.markdown('<span id="kpi-low"></span>', unsafe_allow_html=True)
                if st.button(f"Low\n{low_count}", key="btn_low", use_container_width=True):
                    set_severity('Low')
            with r2_c3:
                st.markdown('<span id="kpi-info"></span>', unsafe_allow_html=True)
                if st.button(f"Info\n{info_count}", key="btn_info", use_container_width=True):
                    set_severity('Informational')

            st.caption(f"Currently Showing: **{st.session_state['selected_severity']}** Findings")

            # Filter
            # Ensure safe comparison
            selected_sev = st.session_state['selected_severity']
            if selected_sev == 'Total':
                filtered_df = df
            else:
                filtered_df = df[df['Severity'].astype(str) == selected_sev]

            st.divider()
            
            if filtered_df.empty:
                st.info(f"No findings found for severity: {selected_sev}")
            else:
                # Charts
                r2_1, r2_2 = st.columns(2)
                
                # Helper for Selection
                def handle_selection(key_name, original_fig):
                    # Check if event
                    if key_name in st.session_state and st.session_state[key_name].get('selection'):
                        sel = st.session_state[key_name]['selection']
                        if 'points' in sel and sel['points']:
                            # Point selected
                            point = sel['points'][0]
                            # Try to find label: label, x, or customdata
                            label = point.get('label') or point.get('x')
                            if label:
                                # Apply filter logic based on chart type
                                if "severity" in key_name: set_severity(label)
                                # For others we might filter DF directly, but current logic filters by Severity.
                                # Let's stick to Severity filtering for now or simple toast
                                if "severity" not in key_name:
                                    st.toast(f"Drill down: {label} (Filtering implemented for Severity only currently)")
                                    
                # --- CHARTS SECTION (2 Cols per reference) ---
                # Left: Issue Severity (Pie)
                with r2_1:
                    st.markdown("##### Issue Severity")
                    try:
                        fig_pie = px.pie(filtered_df, names='Severity', color='Severity', 
                                         color_discrete_map=REQUIRED_COLORS, hole=0.5)
                        fig_pie.update_layout(showlegend=False, margin=dict(t=20, b=20, l=20, r=20))
                        fig_pie = update_chart_layout(fig_pie)
                        # Center Text
                        crit_val = len(filtered_df[filtered_df['Severity'] == 'Critical'])
                        fig_pie.update_layout(annotations=[dict(text=f"Critical<br>{crit_val}", x=0.5, y=0.5, font_size=20, showarrow=False)])
                        
                        st.plotly_chart(fig_pie, use_container_width=True, key="chart_severity", on_select="rerun", selection_mode="points")
                        handle_selection("chart_severity", fig_pie)
                        figures['Severity Distribution'] = fig_pie
                    except: st.error("Chart Error")

                # Right: Vulnerability Count (Bar)
                with r2_2:
                    st.markdown("##### Vulnerability Count")
                    try:
                        # Group by Severity for Bar Chart (or Category). Reference shows Bar chart.
                        # Reference: "Vulnerability Count" - Vertical Bars.
                        # Let's show Severity counts as bars
                        sev_counts = filtered_df['Severity'].value_counts().reindex(['Critical','High','Medium','Low','Info']).fillna(0).reset_index(name='Count')
                        if 'index' in sev_counts.columns: sev_counts.rename(columns={'index': 'Severity'}, inplace=True)
                        
                        fig_bar = px.bar(sev_counts, x='Severity', y='Count', color='Severity', color_discrete_map=REQUIRED_COLORS)
                        fig_bar.update_layout(showlegend=False, margin=dict(t=20, b=20, l=20, r=20))
                        fig_bar = update_chart_layout(fig_bar)
                        
                        st.plotly_chart(fig_bar, use_container_width=True, key="chart_vsearch", on_select="rerun", selection_mode="points")
                        handle_selection("chart_vsearch", fig_bar)
                        figures['Severity Counts'] = fig_bar
                    except: st.error("Chart Error")
                
                # (Optional) We can add more rows if needed, but the image focuses on these 2.
                
                # --- FINDINGS TABLE ---

                st.divider()
                st.subheader(f"Analysis Findings ({selected_sev})")
                
                # Styled Dataframe for Dark Mode
                # Styled Dataframe for Dark Mode
                if st.session_state['theme'] == 'Dark':
                    st.dataframe(
                         filtered_df.style.set_properties(**{
                             'background-color': '#262730', 
                             'color': 'white', 
                             'border-color': '#41444C'
                         }).set_table_styles([
                             {'selector': 'th', 'props': [('background-color', '#262730'), ('color', 'white'), ('border', '1px solid #41444C')]},
                             {'selector': 'td', 'props': [('background-color', '#262730'), ('color', 'white')]}
                         ]), 
                         use_container_width=True
                    )
                else:
                    st.dataframe(filtered_df, use_container_width=True)
                
                # --- DOWNLOAD ACTIONS (Bottom) ---
                st.divider()
                # Guest Restriction: Check if download allowed? 
                # Request says: Guest: Cannot "Download unassigned reports". 
                # If they can see the project, they are assigned. 
                # Employee: Download allowed.
                # So we can keep it open for now as filtering happens upstream.
                
                st.markdown("Download Reports")
                d1, d2, d3 = st.columns([1, 1, 2])
                with d1:
                    # Provide Filtered Data for View, or Full Data?
                    # Usually "Download CSV" implies the data I'm looking at, or the full report. 
                    # Let's provide the Filtered Data to match user expectation of "Not updating".
                    # If they filter to Critical, they might want a Critical CSV.
                    csv_data = generate_csv(filtered_df) 
                    st.download_button("Download CSV Data", csv_data, f"{project_name}_{selected_sev}.csv", "text/csv", key="download_csv_btn", use_container_width=True)
                with d2:
                     if st.button("Generate PDF Report", key="gen_pdf_btn", use_container_width=True):
                         with st.spinner("Generating PDF..."):
                             pdf_bytes = generate_pdf(project_name, filtered_df, figures) 
                             st.download_button("Download PDF", pdf_bytes, f"{project_name}_Report.pdf", "application/pdf", key="download_pdf_final")

        except Exception as e:
            st.error(f"Visualization Error: {e}")
            
    # --- VIEW: PROJECT LIST ---
    else:
        # Default View: Upload or Select Project
        
        # GUEST RESTRICTION: No Import
        if user_role != 'Guest':
            st.markdown("### Import New Scan Report")
            import_c1, import_c2 = st.columns([2, 1])
            with import_c1:
                uploaded_file = st.file_uploader("Upload XML / JSON / CSV", type=['xml', 'json', 'csv'])
            with import_c2:
                # Manual trigger info
                st.info("Supported: Nmap (XML), Zap (JSON), Burp (XML), Nessus (CSV), Checkmarx (CSV)")
            
            if uploaded_file:
                # ... (Parsing Logic) ... 
                # For brevity, reusing existing parsing logic if available or just loading into DF
                # The user previously just had logic to load into session state
                try:
                    df_parsed = parse_file(uploaded_file)
                    st.session_state['current_df'] = df_parsed
                    if 'selected_project_id' in st.session_state: del st.session_state['selected_project_id']
                    st.rerun()
                except Exception as e:
                    st.error(f"Parse Error: {e}")

        # Project Repository
        st.divider()
        st.markdown("### Project Repository")
        
        # RBAC: Fetch Projects
        # Admin/Manager/Employee: See All? Or Employee see own? 
        # Request says: Employee: View all projects.
        # Guest: View ONLY explicitly allocated.
        
        projects = []
        if user_role == 'Guest':
            # Join ProjectAccess
            access_records = session.query(ProjectAccess).filter_by(user_id=user_id).all()
            allowed_ids = [r.project_id for r in access_records]
            projects = session.query(Project).filter(Project.id.in_(allowed_ids)).all()
        else:
            projects = session.query(Project).all()
            
        if projects:
            # Display as List Rows
            for i, p in enumerate(projects):
                with st.container():
                     # Layout: Info (Left) | Actions (Right)
                     c_info, c_action = st.columns([0.7, 0.3])
                     
                     with c_info:
                         st.markdown(f"**{p.project_name}**")
                         st.caption(f"📅 {p.created_date.strftime('%Y-%m-%d')} | 🐛 Vulns: {p.total_vulns}")
                     
                     with c_action:
                         # Right aligned actions
                         # Order: [Delete] [View]
                         ac1, ac2 = st.columns(2)
                         with ac1:
                             if user_role == 'Admin':
                                if st.button("Delete", key=f"del_{p.id}", use_container_width=True):
                                   session.delete(p)
                                   session.commit()
                                   st.rerun()
                         with ac2:
                             if st.button(f"View", key=f"load_{p.id}", use_container_width=True):
                                st.session_state['selected_project_id'] = p.id
                                st.session_state['current_df'] = pd.DataFrame() 
                                st.rerun()
                st.divider()
        else:
             if user_role == 'Guest':
                 st.info("No projects assigned to you. Contact Admin.")
             else:
                 st.info("No saved projects found.")
                 
    session.close()
