from typing import Any
from fastapi import HTTPException

from app.auth.api.dto import (
    GoogleAuthDTO,
    AppleAuthDTO,
    LoginDTO,
    PasswordResetDTO,
    PasswordResetRequestDTO,
    UserRegisterDTO,
)
from app.auth.service.auth_service import AuthService
from pkg.log.logger import Logger


class AuthHandler:
    def __init__(self, auth_service: AuthService, logger: Logger):
        self.auth_service = auth_service
        self.logger = logger

    async def register_user(self, user_data: UserRegisterDTO) -> dict[str, Any]:
        try:
            tokens = await self.auth_service.register_with_email(
                user_data.email,
                user_data.password,
                user_data.name,
            )
            return {
                "message": "Registration successful! Start your journey.",
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": "bearer",
            }
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            self.logger.error(f"Error during registration: {e!s}")
            raise HTTPException(status_code=500, detail="Registration failed")

    async def login(self, login_data: LoginDTO) -> dict[str, Any]:
        try:
            tokens = await self.auth_service.login_with_email(
                login_data.email, login_data.password
            )
            return {
                "message": "Login successful",
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": "bearer",
            }
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            self.logger.error(f"Error during login: {e!s}")
            raise HTTPException(status_code=500, detail="Login failed")

    async def google_auth(self, google_auth_request: GoogleAuthDTO) -> dict[str, Any]:
        try:
            tokens = await self.auth_service.register_with_google(
                google_auth_request.user.id,
                google_auth_request.user.name,
                google_auth_request.user.email,
                google_auth_request.user.image,
                google_auth_request.access_token,
                google_auth_request.id_token
            )
            return {
                "message": "Google authentication successful",
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": "bearer",
            }
        except Exception as e:
            self.logger.error(f"Error during Google authentication: {e!s}")
            raise HTTPException(status_code=500, detail="Google authentication failed")

    async def apple_auth(self, apple_auth_request: AppleAuthDTO) -> dict[str, Any]:
        try:
            tokens = await self.auth_service.register_with_apple(
                apple_auth_request.user.id,
                apple_auth_request.user.name,
                apple_auth_request.user.email,
                apple_auth_request.user.image,
                apple_auth_request.access_token,
                apple_auth_request.id_token
            )
            return {
                "message": "Apple authentication successful",
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": "bearer",
            }
        except Exception as e:
            self.logger.error(f"Error during Apple authentication: {e!s}")
            raise HTTPException(status_code=500, detail="Apple authentication failed")

    async def refresh_token(self, refresh_token: str) -> dict[str, Any]:
        try:
            tokens = await self.auth_service.refresh_token(refresh_token)
            return {
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
                "token_type": "bearer",
            }
        except ValueError as e:
            if str(e) == "Token has expired":
                raise HTTPException(status_code=401, detail="Refresh token has expired")
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            self.logger.error(f"Error refreshing token: {e!s}")
            raise HTTPException(status_code=500, detail="Token refresh failed")

    async def logout(self) -> dict[str, str]:
        return {"message": "Logged out successfully"}

    async def request_password_reset(self, reset_data: PasswordResetRequestDTO):
        try:
            await self.auth_service.request_password_reset(reset_data.email)
            return {"message": "Password reset instructions sent to email"}
        except Exception as e:
            self.logger.error(f"Error requesting password reset: {e!s}")
            raise HTTPException(status_code=500, detail="Failed to send reset instructions")

    async def reset_password(self, reset_data: PasswordResetDTO):
        try:
            await self.auth_service.reset_password(
                reset_data.email, 
                reset_data.token, 
                reset_data.new_password
            )
            return {"message": "Password reset successful"}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            self.logger.error(f"Error resetting password: {e!s}")
            raise HTTPException(status_code=500, detail="Password reset failed")