import random
import string
from datetime import datetime, timedelta
from typing import Any

import bcrypt
from fastapi import HTTPException
from google.auth.transport import requests
from google.oauth2 import id_token
from app.user.service.user_service import UserService
from pkg.auth_token_client.client import TokenClient, TokenPayload
from pkg.log.logger import Logger
from pkg.redis.redis_client import RedisClient  # Assuming this is still needed for OTPs

# Redis keys for OTP storage
REDIS_OTP_STRING = "otp_"
REDIS_PASSWORD_RESET_OTP = "password_reset_otp_"

class AuthService:
    def __init__(
        self,
        user_service: UserService,
        token_client: TokenClient,
        redis_client: RedisClient,
        google_oauth_client_id: str,
        apple_oauth_client_id: str,
        logger: Logger,
    ):

        self.token_client = token_client
        self.redis_client = redis_client
        self.google_client_id = google_oauth_client_id
        self.user_service: UserService = user_service
        self.apple_client_id = apple_oauth_client_id
        self.logger = logger

    def _generate_otp(self) -> str:
        """Generate a 6-digit OTP"""
        return "".join(random.choices(string.digits, k=6))

    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt).decode()

    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode(), hashed.encode())

    def _create_tokens(
        self,
        user_id: str,
        email: str,
        joined_org: bool = False,  # Simplified - default to False
        role: str = "MEMBER",
        org_id: str | None = None,
    ) -> dict[str, str]:
        """Create access and refresh tokens"""
        payload = TokenPayload(
            user_id=user_id,
            joined_org=joined_org,
            role=role,
            org_id=org_id,
            email=email
        )
        return self.token_client.create_tokens(payload)

    async def register_with_email(
        self, email: str, password: str, name: str
    ) -> dict[str, str]:
        """Register a new user with email and password"""
        try:
            # Check if user already exists
            existing_user = await self.user_service.get_user_by_email(email)
            if existing_user:
                raise HTTPException(status_code=400, detail="Email already registered. Please login.")
            
            # Hash the password
            hashed_password = self._hash_password(password)
            
            # Create the user directly without email verification for simplicity
            user_aggregate = await self.user_service.create_user(
                email=email,
                password_hash=hashed_password,
                name=name,
                is_email_verified=True,  # Mark as verified immediately
                auth_provider="email"
            )
            
            # Create and return tokens
            tokens = self._create_tokens(
                user_id=user_aggregate.user.id,
                email=user_aggregate.user.email,
                joined_org=user_aggregate.user.joined_org
            )
            
            return {
                "message": "Registration successful! Start your journey.",
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": "bearer",
            }
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            self.logger.error(f"Error during email registration: {e!s}")
            raise HTTPException(status_code=500, detail="Registration failed")

    async def login_with_email(self, email: str, password: str) -> dict[str, str]:
        """Login with email and password"""
        try:
            user_aggregate = await self.user_service.get_user_by_email(email)
            
            if not user_aggregate or not user_aggregate.user:
                raise HTTPException(status_code=401, detail="Invalid email or password")
            
            # Verify password
            if not self._verify_password(password, user_aggregate.user.password_hash):
                raise HTTPException(status_code=401, detail="Invalid email or password")
            
            # Check if user is verified (if verification is required)
            if not user_aggregate.user.is_email_verified:
                raise HTTPException(status_code=403, detail="Please verify your email before logging in")
            
            # Create and return tokens
            tokens = self._create_tokens(
                user_id=user_aggregate.user.id,
                email=user_aggregate.user.email,
                joined_org=user_aggregate.user.joined_org
            )
            
            return {
                "message": "Login successful",
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": "bearer",
            }
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            self.logger.error(f"Error during email login: {e!s}")
            raise HTTPException(status_code=500, detail="Login failed")

    async def register_with_google(
        self, 
        google_user_id: str, 
        name: str, 
        email: str, 
        image_url: str | None,
        access_token: str,
        id_token: str
    ) -> dict[str, str]:
        """Register or login with Google"""
        try:
            # Verify the ID token from Google
            request = requests.Request()
            id_info = id_token.verify_oauth2_token(
                id_token,  # The ID token from the frontend
                request,
                self.google_client_id,
            )

            # Verify the token is intended for your application
            if id_info["aud"] != self.google_client_id:
                raise ValueError("Invalid audience")

            # Verify the issuer
            if id_info["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
                raise ValueError("Invalid issuer")

            # Verify email from token matches provided email
            if id_info["email"] != email:
                raise ValueError("Email mismatch")
                
            if not id_info.get("email_verified"):
                raise ValueError("Email not verified by Google")

            # Check if user already exists
            existing_user_aggregate = await self.user_service.get_user_by_email(email)
            
            if existing_user_aggregate and existing_user_aggregate.user:
                # Check if existing user used a different auth provider
                if existing_user_aggregate.user.auth_provider != "google":
                    raise HTTPException(
                        status_code=400,
                        detail=f"Email already registered with {existing_user_aggregate.user.auth_provider} authentication"
                    )
                
                # Return tokens for existing user
                tokens = self._create_tokens(
                    user_id=existing_user_aggregate.user.id,
                    email=existing_user_aggregate.user.email,
                    joined_org=existing_user_aggregate.user.joined_org
                )
                return {
                    "message": "Google authentication successful",
                    "access_token": tokens["access_token"],
                    "refresh_token": tokens["refresh_token"],
                    "token_type": "bearer",
                }

            # Create new user with Google auth
            user_aggregate = await self.user_service.create_user(
                email=email,
                password_hash="",  # No password for Google auth
                name=name,
                is_email_verified=True,  # Google has verified the email
                auth_provider="google",
                # Optionally store auth provider details if needed
                auth_provider_detail={
                    "google_user_id": google_user_id,
                    "access_token": access_token,
                    "id_token": id_token
                }
            )
            
            # Create and return tokens
            tokens = self._create_tokens(
                user_id=user_aggregate.user.id,
                email=user_aggregate.user.email,
                joined_org=user_aggregate.user.joined_org
            )
            
            return {
                "message": "Google authentication successful",
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": "bearer",
            }

        except ValueError as e:
            self.logger.error(f"Google token verification failed: {e!s}")
            raise HTTPException(status_code=400, detail=f"Invalid token: {e!s}")
        except Exception as e:
            self.logger.error(f"Google authentication error: {e!s}")
            raise HTTPException(status_code=500, detail="Authentication failed")

    async def register_with_apple(
        self, 
        apple_user_id: str, 
        name: str, 
        email: str | None, 
        image_url: str | None,
        access_token: str,
        id_token: str
    ) -> dict[str, str]:
        """Register or login with Apple"""
        try:
            # Apple token verification is more complex and usually handled server-side
            # For simplicity, we'll trust the frontend validation here
            # In production, you should verify the Apple ID token properly
            
            # If email is provided and verified by frontend, use it
            if not email:
                raise ValueError("Email is required for Apple authentication")
            
            # Check if user already exists
            existing_user_aggregate = await self.user_service.get_user_by_email(email)
            
            if existing_user_aggregate and existing_user_aggregate.user:
                # Check if existing user used a different auth provider
                if existing_user_aggregate.user.auth_provider != "apple":
                    raise HTTPException(
                        status_code=400,
                        detail=f"Email already registered with {existing_user_aggregate.user.auth_provider} authentication"
                    )
                
                # Return tokens for existing user
                tokens = self._create_tokens(
                    user_id=existing_user_aggregate.user.id,
                    email=existing_user_aggregate.user.email,
                    joined_org=existing_user_aggregate.user.joined_org
                )
                return {
                    "message": "Apple authentication successful",
                    "access_token": tokens["access_token"],
                    "refresh_token": tokens["refresh_token"],
                    "token_type": "bearer",
                }

            # Create new user with Apple auth
            user_aggregate = await self.user_service.create_user(
                email=email,
                password_hash="",  # No password for Apple auth
                name=name,
                is_email_verified=True,  # Apple has verified the email (assumed)
                auth_provider="apple",
                # Optionally store auth provider details if needed
                auth_provider_detail={
                    "apple_user_id": apple_user_id,
                    "access_token": access_token,
                    "id_token": id_token
                }
            )
            
            # Create and return tokens
            tokens = self._create_tokens(
                user_id=user_aggregate.user.id,
                email=user_aggregate.user.email,
                joined_org=user_aggregate.user.joined_org
            )
            
            return {
                "message": "Apple authentication successful",
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": "bearer",
            }

        except ValueError as e:
            self.logger.error(f"Apple authentication failed: {e!s}")
            raise HTTPException(status_code=400, detail=f"Invalid Apple authentication: {e!s}")
        except Exception as e:
            self.logger.error(f"Apple authentication error: {e!s}")
            raise HTTPException(status_code=500, detail="Authentication failed")

    async def refresh_token(self, refresh_token: str) -> dict[str, str]:
        """Generate new access token using refresh token"""
        try:
            payload = self.token_client.decode_token(refresh_token, is_refresh=True)

            user_aggregate = await self.user_service.get_user_by_id(payload["user_id"])
            if not user_aggregate or not user_aggregate.user:
                raise HTTPException(status_code=401, detail="User not found")

            # Create new tokens
            tokens = self._create_tokens(
                user_id=user_aggregate.user.id,
                email=user_aggregate.user.email,
                joined_org=user_aggregate.user.joined_org
            )
            
            return {
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": "bearer",
            }

        except ValueError as e:
            # Token expired or invalid
            raise HTTPException(status_code=401, detail=str(e))
        except Exception as e:
            self.logger.error(f"Error refreshing token: {e!s}")
            raise HTTPException(status_code=500, detail="Token refresh failed")

    async def request_password_reset(self, email: str) -> None:
        """Send password reset OTP to user email"""
        user_aggregate = await self.user_service.get_user_by_email(email)
        if not user_aggregate or not user_aggregate.user:
            # Don't reveal if user exists to prevent email enumeration
            self.logger.info(f"Password reset requested for non-existent email: {email}")
            return  # Still return success to prevent enumeration
            
        # Skip OTP for OAuth users who don't have passwords
        if user_aggregate.user.auth_provider != "email":
            raise HTTPException(
                status_code=400, 
                detail=f"This account uses {user_aggregate.user.auth_provider} authentication. Please log in with {user_aggregate.user.auth_provider}."
            )

        # Generate and store OTP in Redis
        otp = self._generate_otp()
        self.redis_client.set_value(REDIS_PASSWORD_RESET_OTP + email, otp, expiry=600)
        
        # In a real app, send email here using smtp_client
        # await self.smtp_client.send_email(...)
        
        self.logger.info(f"Password reset OTP sent to: {email}")

    async def reset_password(self, email: str, token: str, new_password: str) -> None:
        """Reset user password with OTP"""
        user_aggregate = await self.user_service.get_user_by_email(email)
        if not user_aggregate or not user_aggregate.user:
            raise HTTPException(status_code=404, detail="User not found")
            
        if user_aggregate.user.auth_provider != "email":
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot reset password for {user_aggregate.user.auth_provider} account"
            )
            
        # Get stored OTP from Redis
        stored_otp = self.redis_client.get_value(REDIS_PASSWORD_RESET_OTP + email)
        if not stored_otp:
            raise HTTPException(status_code=400, detail="OTP expired or not requested")
            
        # Verify OTP
        if str(stored_otp) != token:
            raise HTTPException(status_code=400, detail="Invalid OTP")
            
        # Hash new password
        hashed_password = self._hash_password(new_password)
        
        # Update user password
        await self.user_service.update_user_password(user_aggregate.user.id, hashed_password)
        
        # Delete OTP after successful password reset
        self.redis_client.delete(REDIS_PASSWORD_RESET_OTP + email)
        
        self.logger.info(f"Password reset successful for user: {email}")