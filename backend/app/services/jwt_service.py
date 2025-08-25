"""
JWT Authentication Service

This module provides JWT token generation, validation, and management
for the authentication system.
"""

import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import jwt
import redis
from fastapi import HTTPException, status
from jwt import ExpiredSignatureError, InvalidTokenError

# Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Redis configuration for token blacklist
REDIS_URL = os.getenv("REDIS_URL", os.getenv("REDIS_CLOUD_URL", "redis://localhost:6379"))


class JWTService:
    """Service for handling JWT authentication tokens."""
    
    def __init__(self):
        """Initialize JWT service with Redis connection for blacklist."""
        try:
            self.redis_client = redis.from_url(REDIS_URL, decode_responses=True)
            self.redis_client.ping()
        except Exception as e:
            print(f"Warning: Redis connection failed: {e}. Token blacklist disabled.")
            self.redis_client = None
            
    def _generate_jti(self) -> str:
        """Generate a unique JWT ID (jti) for token tracking."""
        return hashlib.sha256(
            f"{time.time()}{secrets.token_urlsafe(16)}".encode()
        ).hexdigest()[:32]
    
    def create_access_token(
        self, 
        user_data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create a JWT access token.
        
        Args:
            user_data: Dictionary containing user information
            expires_delta: Optional custom expiration time
            
        Returns:
            Encoded JWT token string
        """
        to_encode = user_data.copy()
        
        # Set expiration
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        # Add standard JWT claims
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": self._generate_jti(),
            "type": "access"
        })
        
        # Encode the token
        encoded_jwt = jwt.encode(
            to_encode, 
            JWT_SECRET_KEY, 
            algorithm=JWT_ALGORITHM
        )
        
        return encoded_jwt
    
    def create_refresh_token(
        self, 
        user_data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create a JWT refresh token.
        
        Args:
            user_data: Dictionary containing user information
            expires_delta: Optional custom expiration time
            
        Returns:
            Encoded JWT refresh token string
        """
        to_encode = {
            "sub": user_data.get("sub", user_data.get("email")),
            "uid": user_data.get("uid", user_data.get("id"))
        }
        
        # Set expiration
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                days=JWT_REFRESH_TOKEN_EXPIRE_DAYS
            )
        
        # Add standard JWT claims
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": self._generate_jti(),
            "type": "refresh"
        })
        
        # Encode the token
        encoded_jwt = jwt.encode(
            to_encode, 
            JWT_SECRET_KEY, 
            algorithm=JWT_ALGORITHM
        )
        
        return encoded_jwt
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify and decode a JWT token.
        
        Args:
            token: JWT token string to verify
            
        Returns:
            Decoded token payload
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            # Check if token is blacklisted
            if self._is_token_blacklisted(token):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )
            
            # Decode and verify the token
            payload = jwt.decode(
                token, 
                JWT_SECRET_KEY, 
                algorithms=[JWT_ALGORITHM]
            )
            
            return payload
            
        except ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except InvalidTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            )
    
    def verify_refresh_token(self, token: str) -> Dict[str, Any]:
        """
        Verify a refresh token specifically.
        
        Args:
            token: Refresh token string to verify
            
        Returns:
            Decoded token payload
            
        Raises:
            HTTPException: If token is invalid or not a refresh token
        """
        payload = self.verify_token(token)
        
        # Verify it's a refresh token
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        return payload
    
    def refresh_access_token(self, refresh_token: str) -> Tuple[str, str]:
        """
        Generate new access and refresh tokens from a valid refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            Tuple of (new_access_token, new_refresh_token)
        """
        # Verify the refresh token
        payload = self.verify_refresh_token(refresh_token)
        
        # Blacklist the old refresh token
        self.blacklist_token(refresh_token)
        
        # Create new user data from refresh token payload
        user_data = {
            "sub": payload.get("sub"),
            "uid": payload.get("uid"),
            "email": payload.get("sub")  # sub contains email in refresh token
        }
        
        # Generate new tokens
        new_access_token = self.create_access_token(user_data)
        new_refresh_token = self.create_refresh_token(user_data)
        
        return new_access_token, new_refresh_token
    
    def blacklist_token(self, token: str) -> bool:
        """
        Add a token to the blacklist (for logout).
        
        Args:
            token: Token to blacklist
            
        Returns:
            True if successfully blacklisted
        """
        if not self.redis_client:
            return False
        
        try:
            # Decode to get expiration time
            payload = jwt.decode(
                token, 
                JWT_SECRET_KEY, 
                algorithms=[JWT_ALGORITHM],
                options={"verify_exp": False}
            )
            
            # Calculate TTL (time until token would naturally expire)
            exp = payload.get("exp", 0)
            ttl = max(0, exp - int(time.time()))
            
            # Store in Redis with TTL
            jti = payload.get("jti")
            if jti:
                self.redis_client.setex(
                    f"blacklist:{jti}",
                    ttl,
                    json.dumps({
                        "token": token[:20] + "...",  # Store partial token for logging
                        "blacklisted_at": datetime.now(timezone.utc).isoformat()
                    })
                )
                return True
                
        except Exception as e:
            print(f"Error blacklisting token: {e}")
            
        return False
    
    def _is_token_blacklisted(self, token: str) -> bool:
        """
        Check if a token is in the blacklist.
        
        Args:
            token: Token to check
            
        Returns:
            True if token is blacklisted
        """
        if not self.redis_client:
            return False
        
        try:
            # Decode to get JTI
            payload = jwt.decode(
                token, 
                JWT_SECRET_KEY, 
                algorithms=[JWT_ALGORITHM],
                options={"verify_exp": False}
            )
            
            jti = payload.get("jti")
            if jti:
                return self.redis_client.exists(f"blacklist:{jti}") > 0
                
        except Exception:
            pass
            
        return False
    
    def extract_user_from_token(self, token: str) -> Dict[str, Any]:
        """
        Extract user information from a valid token.
        
        Args:
            token: Valid JWT token
            
        Returns:
            Dictionary containing user information
        """
        payload = self.verify_token(token)
        
        return {
            "uid": payload.get("uid"),
            "email": payload.get("email", payload.get("sub")),
            "name": payload.get("name"),
            "roles": payload.get("roles", ["user"]),
            "organizations": payload.get("organizations", ["default"]),
            "admin": payload.get("admin", False)
        }


# Singleton instance
jwt_service = JWTService()


# Convenience functions
def create_access_token(user_data: Dict[str, Any]) -> str:
    """Create an access token for a user."""
    return jwt_service.create_access_token(user_data)


def create_refresh_token(user_data: Dict[str, Any]) -> str:
    """Create a refresh token for a user."""
    return jwt_service.create_refresh_token(user_data)


def verify_token(token: str) -> Dict[str, Any]:
    """Verify and decode a token."""
    return jwt_service.verify_token(token)


def blacklist_token(token: str) -> bool:
    """Blacklist a token (for logout)."""
    return jwt_service.blacklist_token(token)


def refresh_tokens(refresh_token: str) -> Tuple[str, str]:
    """Refresh access and refresh tokens."""
    return jwt_service.refresh_access_token(refresh_token)
