from typing import Any
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.user.entities.aggregate import UserAggregate
from app.user.entities.entity import User as UserEntity
from app.user.repository.schema.user import User
from app.user.service.user_service import IUserRepository
from pkg.log.logger import Logger


class UserRepository(IUserRepository):
    def __init__(self,  db_session_factory , logger: Logger):
        self.db_session_factory = db_session_factory
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
        google_id: str | None = None,
        image_url: str | None = None
    ) -> UserAggregate:
        """Create a new user"""
        if auth_provider_detail is None:
            auth_provider_detail = {}
        try:
            async with self.db_session_factory() as session:
                async with session.begin():
                    user = User(
                        email=email,
                        password_hash=password_hash,
                        auth_provider=auth_provider,
                        auth_provider_detail=auth_provider_detail,
                        name=name,
                        phone="",
                        image_url="",
                        is_email_verified=is_email_verified,
                        profile_colour=profile_colour,
                    )
                    session.add(user)

                await session.refresh(user)

                user_entity = UserEntity(
                    id=user.uid,
                    email=user.email,
                    password_hash=user.password_hash,
                    auth_provider=user.auth_provider,
                    is_email_verified=user.is_email_verified,
                    name=user.name or "",
                    created_at=user.created_at,
                    updated_at=user.updated_at,
                    profile_colour=user.profile_colour or "",
                )

                return UserAggregate(user=user_entity, events=["UserCreated"])

        except Exception as e:
            self.logger.error(f"Error creating user: {e!s}")
            raise HTTPException(status_code=500, detail="Failed to create user")

    async def get_user_by_email(self, email: str) -> UserAggregate | None:
        try:
            async with self.db_session_factory() as session:
                result = await session.execute(select(User).filter(User.email == email))
                user = result.scalars().first()
                if not user:
                    return None

                user_entity = UserEntity(
                    id=user.uid,
                    email=user.email,
                    password_hash=user.password_hash,
                    auth_provider=user.auth_provider,
                    is_email_verified=user.is_email_verified,
                    name=user.name or "",
                    phone=user.phone or "",
                    image_url=user.image_url or "",
                    is_profile_created=user.is_profile_created,
                    profile_colour=user.profile_colour or "",
                    created_at=user.created_at,
                    updated_at=user.updated_at,
                )
                return UserAggregate(user=user_entity)

        except Exception as e:
            self.logger.error(f"Error getting user by email: {e!s}")
            raise HTTPException(status_code=500, detail="Failed to fetch user by email")

    async def get_user_by_id(self, user_id: str) -> UserAggregate | None:
        try:
            async with self.db_session_factory() as session:
                result = await session.execute(select(User).filter(User.uid == user_id))
                user = result.scalars().first()
                if not user:
                    return None

                user_entity = UserEntity(
                    id=user.uid,
                    email=user.email,
                    password_hash=user.password_hash,
                    auth_provider=user.auth_provider,
                    is_email_verified=user.is_email_verified,
                    name=user.name or "",
                    phone=user.phone or "",
                    image_url=user.image_url or "",
                    is_profile_created=user.is_profile_created,
                    profile_colour=user.profile_colour or "",
                    created_at=user.created_at,
                    updated_at=user.updated_at,
                )
                return UserAggregate(user=user_entity)

        except Exception as e:
            self.logger.error(f"Error getting user by ID: {e!s}")
            raise HTTPException(status_code=500, detail="Failed to fetch user by ID")

    async def update_email_verification(self, user_id: str, is_verified: bool) -> UserAggregate:
        try:
            async with self.db_session_factory() as session:
                async with session.begin():
                    result = await session.execute(select(User).filter(User.uid == user_id))
                    user = result.scalars().first()
                    if not user:
                        raise HTTPException(status_code=404, detail="User not found")

                    user.is_email_verified = is_verified

                await session.refresh(user)

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
            self.logger.error(f"Error updating email verification: {e!s}")
            raise HTTPException(status_code=500, detail="Failed to update email verification")

    async def update_user_password(self, user_id: str, password_hash: str) -> UserAggregate:
        try:
            async with self.db_session_factory() as session:
                async with session.begin():
                    result = await session.execute(select(User).filter(User.uid == user_id))
                    user = result.scalars().first()
                    if not user:
                        raise HTTPException(status_code=404, detail="User not found")

                    if user.auth_provider != "email":
                        raise HTTPException(
                            status_code=400,
                            detail=f"Cannot update password for {user.auth_provider} authentication"
                        )

                    user.password_hash = password_hash

                await session.refresh(user)

                user_entity = UserEntity(
                    id=user.uid,
                    email=user.email,
                    password_hash=user.password_hash,
                    auth_provider=user.auth_provider,
                    is_email_verified=user.is_email_verified,
                    name=user.name or "",
                    phone=user.phone or "",
                    image_url=user.image_url or "",
                    is_profile_created=user.is_profile_created,
                    profile_colour=user.profile_colour or "",
                    created_at=user.created_at,
                    updated_at=user.updated_at,
                )

                return UserAggregate(user=user_entity, events=["PasswordUpdated"])

        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error updating user password: {e!s}")
            raise HTTPException(status_code=500, detail="Failed to update password")

    async def delete_user(self, user_id: str) -> bool:
        try:
            async with self.db_session_factory() as session:
                async with session.begin():
                    result = await session.execute(select(User).filter(User.uid == user_id))
                    user = result.scalars().first()
                    if not user:
                        raise HTTPException(status_code=404, detail="User not found")

                    await session.delete(user)

            return True

        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error deleting user: {e!s}")
            raise HTTPException(status_code=500, detail="Failed to delete user")
