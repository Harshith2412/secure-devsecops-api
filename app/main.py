"""
Secure DevSecOps API Platform - Main Application
FastAPI application with comprehensive security controls.
"""
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from app.config import get_settings
from app.security.headers import SecurityHeadersMiddleware
from app.api import routes_auth, routes_users, routes_demo
from app.db.base import init_db
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

settings = get_settings()

# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Zero-Trust Secure API Platform with DevSecOps Pipeline",
    docs_url="/docs" if settings.debug else None,  # Disable in production
    redoc_url="/redoc" if settings.debug else None,
)

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)


# Exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Custom handler for validation errors.
    Returns 400 with details about validation failures.
    """
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "detail": "Validation error",
            "errors": exc.errors()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    General exception handler.
    Logs the error and returns a generic 500 response.
    """
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    logger.info("Starting Secure DevSecOps API Platform")
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


# Health check endpoint
@app.get("/health", tags=["system"])
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "version": settings.app_version,
        "app": settings.app_name
    }


# Include routers
app.include_router(routes_auth.router)
app.include_router(routes_users.router)
app.include_router(routes_demo.router)


# Root endpoint
@app.get("/", tags=["system"])
async def root():
    """Root endpoint with API information."""
    return {
        "message": "Secure DevSecOps API Platform",
        "version": settings.app_version,
        "docs": "/docs" if settings.debug else "Documentation disabled in production",
        "health": "/health"
    }