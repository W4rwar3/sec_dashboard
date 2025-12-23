from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Enum
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime
import enum

Base = declarative_base()

class UserRole(enum.Enum):
    ADMIN = "Admin"
    MANAGER = "Manager"
    EMPLOYEE = "Employee"

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String) # For local auth
    full_name = Column(String)
    avatar_url = Column(String)
    role = Column(String, default="Employee")
    team_id = Column(Integer, ForeignKey('teams.id'))

    # Relationships
    teams_managed = relationship("Team", back_populates="manager", foreign_keys="Team.manager_id")
    team = relationship("Team", back_populates="members", foreign_keys=[team_id])
    project_access = relationship("ProjectAccess", back_populates="user")
    projects_owned = relationship("Project", back_populates="owner")

class Team(Base):
    __tablename__ = 'teams'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    manager_id = Column(Integer, ForeignKey('users.id'))

    manager = relationship("User", back_populates="teams_managed", foreign_keys=[manager_id])
    members = relationship("User", back_populates="team", foreign_keys="User.team_id")

class Project(Base):
    __tablename__ = 'projects'
    id = Column(Integer, primary_key=True)
    project_name = Column(String, nullable=False)
    created_date = Column(DateTime, default=datetime.utcnow)
    total_vulns = Column(Integer, default=0)
    owner_id = Column(Integer, ForeignKey('users.id'))

    owner = relationship("User", back_populates="projects_owned")
    vulnerabilities = relationship("Vulnerability", back_populates="project", cascade="all, delete-orphan")
    access_list = relationship("ProjectAccess", back_populates="project")

class ProjectAccess(Base):
    __tablename__ = 'project_access'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    project_id = Column(Integer, ForeignKey('projects.id'))
    
    user = relationship("User", back_populates="project_access")
    project = relationship("Project", back_populates="access_list")

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'))
    severity = Column(String, nullable=False)  # Critical, High, Medium, Low, Info
    vuln_name = Column(String, nullable=False)
    description = Column(Text)
    owasp_category = Column(String)
    status = Column(String, default="Open")
    file_location = Column(String) # For code analysis findings

    project = relationship("Project", back_populates="vulnerabilities")

# Setup Database
engine = create_engine('sqlite:///vapt_dashboard.db', connect_args={'check_same_thread': False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
