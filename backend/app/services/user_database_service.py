"""
User Database Service

This module handles all database operations for user management.
"""

import os
import secrets
from datetime import datetime, timedelta
from typing import List, Optional

from bson import ObjectId
from pymongo import ASCENDING, MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.models.user import User, UserCreate, UserPasswordUpdate, UserUpdate


class UserDatabaseService:
    """Service for handling user database operations."""
    
    def __init__(self):
        """Initialize database connection."""
        # Get MongoDB URI from environment
        mongodb_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
        self.client = MongoClient(mongodb_uri)
        
        # Get database name
        db_name = os.getenv("MONGODB_DATABASE", "callpilot")
        self.db = self.client[db_name]
        
        # Users collection
        self.collection = self.db.users
        
        # Create indexes
        self._create_indexes()
    
    def _create_indexes(self):
        """Create database indexes for performance."""
        # Unique index on email
        self.collection.create_index(
            [("email", ASCENDING)],
            unique=True,
            name="email_unique_idx"
        )
        
        # Index on verification and reset tokens
        self.collection.create_index(
            [("verification_token", ASCENDING)],
            name="verification_token_idx"
        )
        self.collection.create_index(
            [("reset_token", ASCENDING)],
            name="reset_token_idx"
        )
    
    def create_user(self, user_data: UserCreate) -> User:
        """
        Create a new user in the database.
        
        Args:
            user_data: User creation data
            
        Returns:
            Created user object
            
        Raises:
            ValueError: If email already exists
        """
        # Note: We don't check existence first to avoid race conditions
        # The unique index will handle duplicate prevention atomically
        
        # Create user document
        user_doc = {
            "email": user_data.email,
            "password_hash": User.hash_password(user_data.password),
            "name": user_data.name,
            "roles": user_data.roles or ["user"],
            "organizations": user_data.organizations or ["default"],
            "is_active": True,
            "is_admin": user_data.is_admin,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "last_login": None,
            "login_attempts": 0,
            "locked_until": None,
            "email_verified": False,
            "verification_token": secrets.token_urlsafe(32),
            "reset_token": None,
            "reset_token_expires": None
        }
        
        try:
            # Insert user
            result = self.collection.insert_one(user_doc)
            user_doc["_id"] = str(result.inserted_id)
            
            # Return user object
            return User.from_mongo(user_doc)
            
        except DuplicateKeyError as e:
            raise ValueError("Email already registered") from e
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """
        Get a user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User object or None if not found
        """
        try:
            user_doc = self.collection.find_one({"_id": ObjectId(user_id)})
            return User.from_mongo(user_doc) if user_doc else None
        except Exception:
            return None
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get a user by email.
        
        Args:
            email: User email
            
        Returns:
            User object or None if not found
        """
        user_doc = self.collection.find_one({"email": email.lower()})
        return User.from_mongo(user_doc) if user_doc else None
    
    def update_user(
        self, 
        user_id: str, 
        update_data: UserUpdate
    ) -> Optional[User]:
        """
        Update user information.
        
        Args:
            user_id: User ID
            update_data: Fields to update
            
        Returns:
            Updated user object or None if not found
        """
        # Build update document
        update_doc = {
            k: v for k, v in update_data.dict(exclude_unset=True).items()
        }
        
        if not update_doc:
            return self.get_user_by_id(user_id)
        
        # Add updated timestamp
        update_doc["updated_at"] = datetime.utcnow()
        
        # Update user atomically
        result = self.collection.find_one_and_update(
            {"_id": ObjectId(user_id)},
            {"$set": update_doc},
            return_document=ReturnDocument.AFTER
        )
        
        return User.from_mongo(result) if result else None
    
    def update_password(
        self, 
        user_id: str, 
        password_update: UserPasswordUpdate
    ) -> bool:
        """
        Update user password.
        
        Args:
            user_id: User ID
            password_update: Password update data
            
        Returns:
            True if successful
            
        Raises:
            ValueError: If current password is incorrect
        """
        # Get user
        user = self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Verify current password
        if not user.verify_password(password_update.current_password):
            raise ValueError("Current password is incorrect")
        
        # Hash new password
        new_hash = User.hash_password(password_update.new_password)
        
        # Update password
        result = self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "password_hash": new_hash,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        return result.modified_count > 0
    
    def delete_user(self, user_id: str) -> bool:
        """
        Delete a user (soft delete by marking inactive).
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful
        """
        result = self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "is_active": False,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        return result.modified_count > 0
    
    def verify_login(
        self, 
        email: str, 
        password: str
    ) -> Optional[User]:
        """
        Verify user login credentials.
        
        Args:
            email: User email
            password: User password
            
        Returns:
            User object if credentials valid, None otherwise
        """
        # Get user
        user = self.get_user_by_email(email)
        if not user:
            return None
        
        # Check if account is locked
        if user.is_locked():
            return None
        
        # Verify password
        if user.verify_password(password):
            # Atomically reset login attempts and update last login
            updated_doc = self.collection.find_one_and_update(
                {"_id": ObjectId(user.id)},
                {
                    "$set": {
                        "login_attempts": 0,
                        "locked_until": None,
                        "last_login": datetime.utcnow(),
                        "updated_at": datetime.utcnow()
                    }
                },
                return_document=ReturnDocument.AFTER
            )
            return User.from_mongo(updated_doc) if updated_doc else user
        else:
            # Atomically increment failed attempts
            self.collection.update_one(
                {"_id": ObjectId(user.id)},
                {
                    "$inc": {"login_attempts": 1},
                    "$set": {"updated_at": datetime.utcnow()}
                }
            )
            
            # Check if we need to lock the account
            if user.login_attempts >= 4:  # Will be 5 after increment
                self.collection.update_one(
                    {"_id": ObjectId(user.id)},
                    {
                        "$set": {
                            "locked_until": datetime.utcnow() + timedelta(minutes=30)
                        }
                    }
                )
            return None
    
    def increment_login_attempts(self, user_id: str):
        """Increment failed login attempts for a user."""
        user = self.get_user_by_id(user_id)
        if user:
            user.increment_login_attempts()
            
            update_doc = {
                "login_attempts": user.login_attempts,
                "updated_at": datetime.utcnow()
            }
            
            if user.locked_until:
                update_doc["locked_until"] = user.locked_until
            
            self.collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": update_doc}
            )
    
    def reset_login_attempts(self, user_id: str):
        """Reset login attempts after successful login."""
        self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "login_attempts": 0,
                    "locked_until": None,
                    "last_login": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
            }
        )
    
    def create_password_reset_token(
        self, 
        email: str
    ) -> Optional[str]:
        """
        Create a password reset token for a user.
        
        Args:
            email: User email
            
        Returns:
            Reset token or None if user not found
        """
        user = self.get_user_by_email(email)
        if not user:
            return None
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        reset_expires = datetime.utcnow() + timedelta(hours=1)
        
        # Update user
        self.collection.update_one(
            {"_id": ObjectId(user.id)},
            {
                "$set": {
                    "reset_token": reset_token,
                    "reset_token_expires": reset_expires,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        return reset_token
    
    def reset_password_with_token(
        self, 
        token: str, 
        new_password: str
    ) -> bool:
        """
        Reset password using a reset token.
        
        Args:
            token: Reset token
            new_password: New password
            
        Returns:
            True if successful
        """
        # Find user with valid token
        user_doc = self.collection.find_one({
            "reset_token": token,
            "reset_token_expires": {"$gt": datetime.utcnow()}
        })
        
        if not user_doc:
            return False
        
        # Hash new password
        new_hash = User.hash_password(new_password)
        
        # Update password and clear reset token
        result = self.collection.update_one(
            {"_id": user_doc["_id"]},
            {
                "$set": {
                    "password_hash": new_hash,
                    "reset_token": None,
                    "reset_token_expires": None,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        return result.modified_count > 0
    
    def verify_email_with_token(self, token: str) -> bool:
        """
        Verify email using verification token.
        
        Args:
            token: Verification token
            
        Returns:
            True if successful
        """
        result = self.collection.update_one(
            {"verification_token": token},
            {
                "$set": {
                    "email_verified": True,
                    "verification_token": None,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        return result.modified_count > 0
    
    def list_users(
        self, 
        skip: int = 0, 
        limit: int = 100,
        include_inactive: bool = False
    ) -> List[User]:
        """
        List users with pagination.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            include_inactive: Whether to include inactive users
            
        Returns:
            List of users
        """
        query = {} if include_inactive else {"is_active": True}
        
        cursor = self.collection.find(query).skip(skip).limit(limit)
        return [User.from_mongo(doc) for doc in cursor]


# Singleton instance
user_db_service = UserDatabaseService()
