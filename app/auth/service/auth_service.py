import random
import string
from datetime import datetime, timedelta

import bcrypt
from fastapi import HTTPException
from app.user.service.user_service import UserService
from pkg.log.logger import Logger
from pkg.redis.client import RedisClient
from pkg.smtp_client.client import EmailClient
from pkg.auth_token_client.client import TokenClient, TokenPayload  # For JWT

# Redis keys for OTP storage
REDIS_PASSWORD_RESET_OTP = "password_reset_otp_"

class AuthService:
    def __init__(
        self,
        user_service: UserService,
        token_client: TokenClient,
        redis_client: RedisClient,
        logger: Logger,
        smtp_client: EmailClient,
    ):
        self.user_service = user_service
        self.token_client = token_client
        self.redis_client = redis_client
        self.logger = logger
        self.smtp_client = smtp_client

    def _hash_password(self, password: str) -> str:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt).decode()

    def _verify_password(self, password: str, hashed: str) -> bool:
        return bcrypt.checkpw(password.encode(), hashed.encode())

    def _create_tokens(self, user_id: str, email: str, role: str = "MEMBER") -> dict[str, str]:
        payload = TokenPayload(
            user_id=user_id,
            role=role,
            email=email
        )
        return self.token_client.create_tokens(payload)

    async def register_with_email(self, email: str, password: str, name: str) -> dict[str, str]:
        """Register a new user and return JWT tokens"""
        try:
            existing_user = await self.user_service.get_user_by_email(email)
            if existing_user:
                raise HTTPException(status_code=400, detail="Email already registered. Please login.")

            hashed_password = self._hash_password(password)
            user_aggregate = await self.user_service.create_user(
                email=email,
                password_hash=hashed_password,
                name=name,
                is_email_verified=True,  # no OTP
                auth_provider="email"
            )

            tokens = self._create_tokens(user_id=user_aggregate.user.id, email=email)

            return {
                "message": "Registration successful",
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": "bearer",
            }
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error during registration: {e!s}")
            raise HTTPException(status_code=500, detail="Registration failed")

    async def login_with_email(self, email: str, password: str) -> dict[str, str]:
        """Login and return JWT tokens"""
        try:
            user_aggregate = await self.user_service.get_user_by_email(email)
            if not user_aggregate or not user_aggregate.user:
                raise HTTPException(status_code=401, detail="Invalid email or password")

            if not self._verify_password(password, user_aggregate.user.password_hash):
                raise HTTPException(status_code=401, detail="Invalid email or password")

            tokens = self._create_tokens(user_id=user_aggregate.user.id, email=email)

            return {
                "message": "Login successful",
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": "bearer",
            }
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error during login: {e!s}")
            raise HTTPException(status_code=500, detail="Login failed")

    async def request_password_reset(self, email: str) -> None:
        """Send password reset OTP to email"""
        user_aggregate = await self.user_service.get_user_by_email(email)
        if not user_aggregate or not user_aggregate.user:
            self.logger.info(f"Password reset requested for non-existent email: {email}")
            return

        if user_aggregate.user.auth_provider != "email":
            raise HTTPException(
                status_code=400,
                detail=f"This account uses {user_aggregate.user.auth_provider}. Please log in using it."
            )

        otp = "".join(random.choices(string.digits, k=6))
        self.redis_client.set_value(REDIS_PASSWORD_RESET_OTP + email, otp, expiry=600)

        body = f"Your password reset code is: {otp}"
        await self.smtp_client.send_email(
            to_addresses=[email],
            subject="Your Password Reset Code",
            body=body
        )
        self.logger.info(f"Password reset OTP sent to: {email}")

    async def reset_password(self, email: str, otp: str, new_password: str) -> None:
        """Reset password using OTP"""
        user_aggregate = await self.user_service.get_user_by_email(email)
        if not user_aggregate or not user_aggregate.user:
            raise HTTPException(status_code=404, detail="User not found")

        if user_aggregate.user.auth_provider != "email":
            raise HTTPException(
                status_code=400,
                detail=f"Cannot reset password for {user_aggregate.user.auth_provider} account"
            )

        stored_otp = self.redis_client.get_value(REDIS_PASSWORD_RESET_OTP + email)
        if not stored_otp or str(stored_otp) != otp:
            raise HTTPException(status_code=400, detail="Invalid or expired OTP")

        hashed_password = self._hash_password(new_password)
        await self.user_service.update_user_password(user_aggregate.user.id, hashed_password)

        self.redis_client.delete(REDIS_PASSWORD_RESET_OTP + email)
        self.logger.info(f"Password reset successful for user: {email}")
