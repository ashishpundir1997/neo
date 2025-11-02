import uuid
from abc import ABC, abstractmethod
from typing import Any

from fastapi import HTTPException

from app.user.entities.aggregate import UserAggregate
from pkg.auth_token_client.client import TokenClient, TokenPayload
from pkg.log.logger import Logger



class IUserRepository(ABC):
    @abstractmethod
    async def create_user(
            self,
            email: str,
            password_hash: str,
            is_email_verified: bool,
            name: str,
            auth_provider: str = "email",
            auth_provider_detail: dict = None,
            profile_colour="",
            google_id: str | None = None,
            image_url: str | None = None
    ) -> UserAggregate:
        pass

    @abstractmethod
    async def get_user_by_email(self, email: str) -> UserAggregate | None:
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> UserAggregate | None:
        pass


    @abstractmethod
    async def update_user_password(self, user_id: str, password_hash: str) -> UserAggregate:
        """Update user password hash"""
        pass




class UserService:
    def __init__(
            self,
            user_repository: IUserRepository,
            logger: Logger,
            token_client: TokenClient,
    ):
        self.user_repository = user_repository
        self.logger = logger
        self.token_client = token_client

    async def create_user(
            self,
            email: str,
            password_hash: str,
            name: str,
            is_email_verified: bool,
            auth_provider: str = "email",
            auth_provider_detail: dict = None,
            google_id: str | None = None,
            image_url: str | None = None
    ) -> UserAggregate:
        """Create a new user"""
        existing_user = await self.get_user_by_email(email)
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")

        user = await self.user_repository.create_user(
            email=email,
            password_hash=password_hash,
            auth_provider=auth_provider,
            name=name,
            is_email_verified=is_email_verified,
            auth_provider_detail=auth_provider_detail,
            google_id=google_id,
            image_url=image_url
        )

        return user

    async def get_user_by_email(self, email: str) -> UserAggregate | None:
        """Get user by email"""
        return await self.user_repository.get_user_by_email(email)

    async def get_user_by_id(self, user_id: str) -> UserAggregate | None:
        """Get user by ID"""
        return await self.user_repository.get_user_by_id(user_id)


    async def update_email_verification(
            self, user_id: str, is_verified: bool = True
    ) -> None:
        """Update user's email verification status"""
        await self.user_repository.update_email_verification(user_id, is_verified)
        return

   

    async def get_user_profile(self, user_id: str) -> UserAggregate:
        user = await self.user_repository.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user



    async def update_user_password(self, user_id: str, password_hash: str) -> UserAggregate:
        """Update user's password hash"""
        try:
            user = await self.user_repository.update_user_password(user_id, password_hash)
            return user
        except Exception as e:
            self.logger.error(f"Error updating user password: {e!s}")
            raise HTTPException(status_code=500, detail="Failed to update password")

   

    async def delete_user(self, user_id: str) -> bool:
        """Delete a user"""
        try:
            return await self.user_repository.delete_user(user_id)
        except Exception as e:
            self.logger.error(f"Error deleting user: {e!s}")
            raise HTTPException(status_code=500, detail="Failed to delete user")

   


