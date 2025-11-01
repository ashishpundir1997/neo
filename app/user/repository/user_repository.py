from typing import Any
from uuid import UUID
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.user.entities.aggregate import UserAggregate
from app.user.entities.entity import User as UserEntity
from app.user.repository.schema.user import User
from app.user.service.user_service import IUserRepository
from pkg.log.logger import Logger
from sqlalchemy.future import select

class UserRepository(IUserRepository):
    def __init__(self, db_session: Session, logger: Logger):
        self.db = db_session
        self.logger = logger

    async def create_user(
            self,
            email: str,
            password_hash: str,
            is_email_verified: bool,
            name: str,
            auth_provider: str = "email",
            auth_provider_detail: dict = None,
            profile_colour: str = "",
    ):
        """Create a new user"""
        if auth_provider_detail is None:
            auth_provider_detail = {}
        try:
            user = User(
                email=email,
                password_hash=password_hash,
                auth_provider=auth_provider,
                auth_provider_detail=auth_provider_detail,
                name=name,
                phone="",
                image_url="",
                job_role="",
                is_email_verified=is_email_verified,
                profile_colour=profile_colour,
            )
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)

            user_entity = UserEntity(
                id=user.uid,
                email=user.email,
                password_hash=user.password_hash,
                auth_provider=user.auth_provider,
                is_email_verified=user.is_email_verified,
                job_role=user.job_role,
                created_at=user.created_at,
                updated_at=user.updated_at,
                profile_colour=profile_colour,
            )

            return UserAggregate(user=user_entity, events=["UserCreated"])

        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Error creating user: {e!s}")
            raise

    async def get_user_by_email(self, email: str) -> UserAggregate | None:
        """Get user by email"""
        try:
            user = self.db.query(User).filter(User.email == email).first()
            if not user:
                return None

            user_entity = UserEntity(
                id=user.uid,
                email=user.email,
                password_hash=user.password_hash,
                auth_provider=user.auth_provider,
                job_role=user.job_role,
                image_url=user.image_url,
                is_profile_created=user.is_profile_created,
                is_email_verified=user.is_email_verified,
                created_at=user.created_at,
                updated_at=user.updated_at,
            )
            return UserAggregate(user=user_entity)

        except Exception as e:
            self.logger.error(f"Error getting user by email: {e!s}")
            raise

    async def get_user_by_id(self, user_id: str) -> UserAggregate | None:
        """Get user by ID"""
        try:
            user = self.db.query(User).filter(User.uid == user_id).first()
            if not user:
                return None

            user_entity = UserEntity(
                id=user.uid,
                email=user.email,
                password_hash=user.password_hash,
                auth_provider=user.auth_provider,
                is_email_verified=user.is_email_verified,
                name=user.name,
                phone=user.phone,
                image_url=user.image_url,
                is_profile_created=user.is_profile_created,
                job_role=user.job_role,
                created_at=user.created_at,
                updated_at=user.updated_at,
            )
            return UserAggregate(user=user_entity)

        except Exception as e:
            self.logger.error(f"Error getting user by ID: {e!s}")
            raise e

    async def update_email_verification(
            self, user_id: str, is_verified: bool
    ) -> UserAggregate:
        """Update email verification status"""
        try:
            user = self.db.query(User).filter(User.uid == user_id).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            user.is_email_verified = is_verified
            self.db.commit()
            self.db.refresh(user)

            user_entity = UserEntity(
                id=user.uid,
                email=user.email,
                password_hash=user.password_hash,
                auth_provider=user.auth_provider,
                is_email_verified=user.is_email_verified,
                created_at=user.created_at,
                updated_at=user.updated_at,
            )

            return UserAggregate(user=user_entity, events=["EmailVerificationUpdated"])

        except HTTPException:
            raise
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Error updating email verification: {e!s}")
            raise

    async def update_user_password(self, user_id: str, password_hash: str) -> UserAggregate:
        """Update user password hash"""
        try:
            user = self.db.query(User).filter(User.uid == user_id).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            if user.auth_provider != "email":
                raise HTTPException(
                    status_code=400,
                    detail=f"Cannot update password for {user.auth_provider} authentication"
                )

            user.password_hash = password_hash
            self.db.commit()
            self.db.refresh(user)

            user_entity = UserEntity(
                id=user.uid,
                email=user.email,
                password_hash=user.password_hash,
                auth_provider=user.auth_provider,
                is_email_verified=user.is_email_verified,
                name=user.name,
                phone=user.phone,
                image_url=user.image_url,
                is_profile_created=user.is_profile_created,
                job_role=user.job_role,
                profile_colour=user.profile_colour,
                created_at=user.created_at,
                updated_at=user.updated_at,
            )

            return UserAggregate(user=user_entity, events=["PasswordUpdated"])

        except HTTPException:
            raise
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Error updating user password: {e!s}")
            raise HTTPException(status_code=500, detail="Failed to update password")

    async def delete_user(self, user_id: str) -> bool:
        """Delete a user"""
        try:
            user = self.db.query(User).filter(User.uid == user_id).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            self.db.delete(user)
            self.db.commit()
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Error deleting user: {e!s}")
            raise HTTPException(status_code=500, detail="Failed to delete user")