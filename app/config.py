"""
Configuration management for the Secure API Platform.
All security-critical settings are loaded from environment variables.
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings with secure defaults."""
    
    # Application
    app_name: str = "Secure DevSecOps API"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # Security
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    
    # Database
    database_url: str = "mysql+pymysql://secureuser:securepass@db:3306/securedb"
    
    # Rate Limiting
    rate_limit_login: int = 5  # attempts per minute
    rate_limit_register: int = 3  # attempts per minute
    rate_limit_refresh: int = 10  # attempts per minute
    
    # Password Policy
    min_password_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = True
    
    # Security Headers
    csp_policy: str = "default-src 'self'; script-src 'self'; object-src 'none';"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()