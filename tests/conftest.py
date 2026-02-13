"""
Pytest configuration and fixtures.
Provides test database and client fixtures.
"""
import pytest
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.db.base import Base, get_db
from app.security.hashing import hash_password
from app.config import get_settings

# Use in-memory SQLite for tests or MySQL if in Docker
if os.getenv("TESTING_IN_DOCKER"):
    # Use a separate test database in MySQL
    TEST_DATABASE_URL = "mysql+pymysql://secureuser:securepass@db:3306/testdb"
else:
    # Use SQLite for local testing
    TEST_DATABASE_URL = "sqlite:///./test.db"

# Create test engine
if "sqlite" in TEST_DATABASE_URL:
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(TEST_DATABASE_URL)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db():
    """Create a fresh database for each test."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    """Create a test client with test database."""
    def override_get_db():
        try:
            yield db
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(db):
    """Create a test user."""
    from app.db.models import User
    user = User(
        email="test@example.com",
        hashed_password=hash_password("TestPassword123!"),
        full_name="Test User",
        role="user",
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def test_admin(db):
    """Create a test admin user."""
    from app.db.models import User
    admin = User(
        email="admin@example.com",
        hashed_password=hash_password("AdminPassword123!"),
        full_name="Admin User",
        role="admin",
        is_active=True
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)
    return admin


@pytest.fixture
def user_token(client, test_user):
    """Get access token for test user."""
    response = client.post(
        "/auth/login",
        json={"email": "test@example.com", "password": "TestPassword123!"}
    )
    return response.json()["access_token"]


@pytest.fixture
def admin_token(client, test_admin):
    """Get access token for test admin."""
    response = client.post(
        "/auth/login",
        json={"email": "admin@example.com", "password": "AdminPassword123!"}
    )
    return response.json()["access_token"]