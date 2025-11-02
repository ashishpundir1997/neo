import random
import string
from datetime import datetime, timedelta
import os
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
        # 600 seconds = 10 minutes
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
        
        
    async def register_with_google(self, google_id: str, name: str, email: str, image_url: str) -> dict[str, str]:
        """Register or Login user with Google"""
        try:
            existing_user = await self.user_service.get_user_by_email(email)

            if existing_user:
                # If user exists and registered with Google, log in
                if existing_user.user.auth_provider == "google":
                    tokens = self._create_tokens(user_id=existing_user.user.id, email=email)
                    return {
                        "message": "Login successful",
                        "access_token": tokens["access_token"],
                        "refresh_token": tokens["refresh_token"],
                        "token_type": "bearer",
                    }
                else:
                    raise HTTPException(status_code=400, detail="Email already registered with different provider. Please login.")

            # Create user without password for Google auth
            user_aggregate = await self.user_service.create_user(
                email=email,
                password_hash=None,  # No password for Google users
                name=name,
                is_email_verified=True,
                auth_provider="google",
                google_id=google_id,
                image_url=image_url
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
        
        
        
        
    async def handle_google_callback(self, code: str) -> dict[str, str]:
        """Exchange code for token, get user info, register/login user"""
        try:
            # Step 1: Exchange code for access token
            token_url = "https://oauth2.googleapis.com/token"
            data = {
                "code": code,
                "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            }

            async with httpx.AsyncClient() as client:
                token_resp = await client.post(token_url, data=data)
                token_resp.raise_for_status()
                tokens_data = token_resp.json()

            access_token = tokens_data["access_token"]

            # Step 2: Get user info
            userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
            headers = {"Authorization": f"Bearer {access_token}"}
            async with httpx.AsyncClient() as client:
                user_resp = await client.get(userinfo_url, headers=headers)
                user_resp.raise_for_status()
                user_info = user_resp.json()

            # Step 3: Register/Login user
            return await self.register_with_google(
                google_id=user_info["id"],
                name=user_info.get("name", ""),
                email=user_info["email"],
                image_url=user_info.get("picture")
            )

        except httpx.HTTPError as e:
            self.logger.error(f"Error fetching Google user info: {e!s}")
            raise HTTPException(status_code=500, detail="Failed to fetch Google user info")
