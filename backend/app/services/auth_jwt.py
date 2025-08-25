"""
Authentication API Endpoints

This module provides all authentication-related API endpoints.
"""

from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel, EmailStr

from app.models.user import (
    User,
    UserCreate,
    UserLogin,
    UserPasswordUpdate,
    UserResponse,
    TokenResponse,
)
from app.services.jwt_service import jwt_service
from app.services.user_database_service import user_db_service

router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer(auto_error=False)


class MessageResponse(BaseModel):
    """Generic message response."""
    message: str


class PasswordResetRequest(BaseModel):
    """Password reset request model."""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation model."""
    token: str
    new_password: str


class RefreshTokenRequest(BaseModel):
    """Refresh token request model."""
    refresh_token: str


async def get_current_user(
    credentials: HTTPBearer = Depends(security)
) -> User:
    """
    Get the current authenticated user from JWT token.
    
    Args:
        credentials: HTTP Bearer credentials
        
    Returns:
        Current user object
        
    Raises:
        HTTPException: If authentication fails
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        # Verify token and extract user data
        payload = jwt_service.verify_token(credentials.credentials)
        
        # Get user from database
        user = user_db_service.get_user_by_id(payload.get("uid"))
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate) -> TokenResponse:
    """
    Register a new user.
    
    Args:
        user_data: User registration data
        
    Returns:
        Access and refresh tokens with user info
        
    Raises:
        HTTPException: If registration fails
    """
    try:
        # Create user
        user = user_db_service.create_user(user_data)
        
        # Generate tokens
        user_jwt_data = user.to_jwt_payload()
        access_token = jwt_service.create_access_token(user_jwt_data)
        refresh_token = jwt_service.create_refresh_token(user_jwt_data)
        
        # Convert to response model
        user_response = UserResponse(
            id=user.id,
            email=user.email,
            name=user.name,
            roles=user.roles,
            organizations=user.organizations,
            is_active=user.is_active,
            is_admin=user.is_admin,
            created_at=user.created_at,
            updated_at=user.updated_at,
            last_login=user.last_login,
            email_verified=user.email_verified
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=1800,  # 30 minutes in seconds
            user=user_response
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )


@router.post("/login", response_model=TokenResponse)
async def login(
    credentials: UserLogin,
    response: Response
) -> TokenResponse:
    """
    Login with email and password.
    
    Args:
        credentials: Login credentials
        response: FastAPI response object for setting cookies
        
    Returns:
        Access and refresh tokens with user info
        
    Raises:
        HTTPException: If login fails
    """
    # Verify credentials
    user = user_db_service.verify_login(
        credentials.email,
        credentials.password
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Check if account is locked
    if user.is_locked():
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is locked due to too many failed login attempts. Please try again later."
        )
    
    # Generate tokens
    user_jwt_data = user.to_jwt_payload()
    access_token = jwt_service.create_access_token(user_jwt_data)
    refresh_token = jwt_service.create_refresh_token(user_jwt_data)
    
    # Set cookies for web clients
    response.set_cookie(
        key="auth_token",
        value=access_token,
        max_age=1800,  # 30 minutes
        httponly=True,
        samesite="lax",
        secure=False  # Set to True in production with HTTPS
    )
    
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=604800,  # 7 days
        httponly=True,
        samesite="lax",
        secure=False  # Set to True in production with HTTPS
    )
    
    # Convert to response model
    user_response = UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        roles=user.roles,
        organizations=user.organizations,
        is_active=user.is_active,
        is_admin=user.is_admin,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login=user.last_login,
        email_verified=user.email_verified
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=1800,  # 30 minutes in seconds
        user=user_response
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    response: Response,
    current_user: User = Depends(get_current_user),
    refresh_token: Optional[str] = None
) -> MessageResponse:
    """
    Logout the current user.
    
    Args:
        response: FastAPI response object for clearing cookies
        current_user: Current authenticated user
        refresh_token: Optional refresh token to blacklist
        
    Returns:
        Success message
    """
    # Get token from request
    # Note: In production, extract this from the Depends
    # For now, we'll just clear cookies
    
    # Clear cookies
    response.delete_cookie(key="auth_token")
    response.delete_cookie(key="refresh_token")
    
    # Blacklist refresh token if provided
    if refresh_token:
        jwt_service.blacklist_token(refresh_token)
    
    return MessageResponse(message="Successfully logged out")


@router.post("/refresh", response_model=TokenResponse)
async def refresh_tokens(
    request: RefreshTokenRequest,
    response: Response
) -> TokenResponse:
    """
    Refresh access and refresh tokens.
    
    Args:
        request: Refresh token request
        response: FastAPI response object for setting cookies
        
    Returns:
        New access and refresh tokens with user info
        
    Raises:
        HTTPException: If refresh fails
    """
    try:
        # Refresh tokens
        new_access_token, new_refresh_token = jwt_service.refresh_access_token(
            request.refresh_token
        )
        
        # Extract user info from new access token
        payload = jwt_service.verify_token(new_access_token)
        user = user_db_service.get_user_by_id(payload.get("uid"))
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        # Set new cookies
        response.set_cookie(
            key="auth_token",
            value=new_access_token,
            max_age=1800,  # 30 minutes
            httponly=True,
            samesite="lax",
            secure=False  # Set to True in production with HTTPS
        )
        
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token,
            max_age=604800,  # 7 days
            httponly=True,
            samesite="lax",
            secure=False  # Set to True in production with HTTPS
        )
        
        # Convert to response model
        user_response = UserResponse(
            id=user.id,
            email=user.email,
            name=user.name,
            roles=user.roles,
            organizations=user.organizations,
            is_active=user.is_active,
            is_admin=user.is_admin,
            created_at=user.created_at,
            updated_at=user.updated_at,
            last_login=user.last_login,
            email_verified=user.email_verified
        )
        
        return TokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            expires_in=1800,  # 30 minutes in seconds
            user=user_response
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token refresh failed: {str(e)}"
        )


@router.get("/verify", response_model=UserResponse)
async def verify_token(
    current_user: User = Depends(get_current_user)
) -> UserResponse:
    """
    Verify the current authentication token.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User information if token is valid
    """
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        name=current_user.name,
        roles=current_user.roles,
        organizations=current_user.organizations,
        is_active=current_user.is_active,
        is_admin=current_user.is_admin,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
        last_login=current_user.last_login,
        email_verified=current_user.email_verified
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
) -> UserResponse:
    """
    Get current user information.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Current user information
    """
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        name=current_user.name,
        roles=current_user.roles,
        organizations=current_user.organizations,
        is_active=current_user.is_active,
        is_admin=current_user.is_admin,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
        last_login=current_user.last_login,
        email_verified=current_user.email_verified
    )


@router.put("/password", response_model=MessageResponse)
async def update_password(
    password_update: UserPasswordUpdate,
    current_user: User = Depends(get_current_user)
) -> MessageResponse:
    """
    Update current user's password.
    
    Args:
        password_update: Password update data
        current_user: Current authenticated user
        
    Returns:
        Success message
        
    Raises:
        HTTPException: If password update fails
    """
    try:
        success = user_db_service.update_password(
            current_user.id,
            password_update
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password update failed"
            )
        
        return MessageResponse(message="Password updated successfully")
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password update failed: {str(e)}"
        )


@router.post("/password-reset", response_model=MessageResponse)
async def request_password_reset(
    request: PasswordResetRequest
) -> MessageResponse:
    """
    Request a password reset token.
    
    Args:
        request: Password reset request with email
        
    Returns:
        Success message (always returns success for security)
    """
    # Create reset token (returns None if user doesn't exist)
    reset_token = user_db_service.create_password_reset_token(request.email)
    
    # TODO: In production, send reset token via email
    # For now, we'll just log it (remove in production!)
    if reset_token:
        print(f"Password reset token for {request.email}: {reset_token}")
    
    # Always return success for security (don't reveal if email exists)
    return MessageResponse(
        message="If the email exists, a password reset link has been sent"
    )


@router.post("/password-reset/confirm", response_model=MessageResponse)
async def confirm_password_reset(
    request: PasswordResetConfirm
) -> MessageResponse:
    """
    Reset password using a reset token.
    
    Args:
        request: Password reset confirmation with token and new password
        
    Returns:
        Success message
        
    Raises:
        HTTPException: If reset fails
    """
    success = user_db_service.reset_password_with_token(
        request.token,
        request.new_password
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )
    
    return MessageResponse(message="Password reset successfully")


@router.get("/email-verify/{token}", response_model=MessageResponse)
async def verify_email(token: str) -> MessageResponse:
    """
    Verify email address using verification token.
    
    Args:
        token: Email verification token
        
    Returns:
        Success message
        
    Raises:
        HTTPException: If verification fails
    """
    success = user_db_service.verify_email_with_token(token)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token"
        )
    
    return MessageResponse(message="Email verified successfully")
