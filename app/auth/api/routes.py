from fastapi import APIRouter, Response, HTTPException,Depends, Request


from app.auth.api.dto import (
    AppleAuthDTO,
    GoogleAuthDTO,
    LoginDTO,
    PasswordResetDTO,
    PasswordResetRequestDTO,
    RefreshTokenDTO,
    UserRegisterDTO,
    EmailVerificationDTO,
)
from app.auth.api.dependencies import get_auth_handler
from app.auth.api.handlers import AuthHandler


auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


@auth_router.post("/register")
async def register(user_data: UserRegisterDTO, auth_handler: AuthHandler = Depends(get_auth_handler)):
    """Register a new user with email and password"""
    return await auth_handler.register_user(user_data)


@auth_router.post("/login")
async def login(login_data: LoginDTO, response: Response, auth_handler: AuthHandler = Depends(get_auth_handler)):
    """Login with email and password"""
    return await auth_handler.login(login_data)


@auth_router.post("/google")
async def google_auth(
    google_data: GoogleAuthDTO, response: Response, auth_handler: AuthHandler = Depends(get_auth_handler)
):
    """Authenticate with Google"""
    return await auth_handler.google_auth(google_data)


@auth_router.post("/apple")
async def apple_auth(
    apple_data: AppleAuthDTO, response: Response, auth_handler: AuthHandler = Depends(get_auth_handler)
):
    """Authenticate with Apple"""
    return await auth_handler.apple_auth(apple_data)


@auth_router.post("/refresh")
async def refresh_token(
    response: Response, refresh_token_dto: RefreshTokenDTO, auth_handler: AuthHandler = Depends(get_auth_handler)
):
    """Refresh access token"""
    try:
        return await auth_handler.refresh_token(refresh_token_dto.refresh_token)
    except ValueError as e:
        if str(e) == "Token has expired":
            raise HTTPException(status_code=401, detail="Refresh token has expired")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        auth_handler.logger.error(f"Error refreshing token: {e!s}")
        raise HTTPException(status_code=500, detail="Internal server error")


@auth_router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    auth_handler: AuthHandler = Depends(get_auth_handler)
):
    """Logout user by blacklisting tokens"""
    # Access token is required
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Authorization header with Bearer token is required")

    access_token = auth_header.split(" ")[1]

    # Optional refresh token from request body
    refresh_token = None
    try:
        body = await request.json()
        refresh_token = body.get("refresh_token")
    except Exception:
        pass

    return await auth_handler.logout(access_token, refresh_token)


@auth_router.post("/password-reset-request")
async def request_password_reset(
    reset_data: PasswordResetRequestDTO, auth_handler: AuthHandler = Depends(get_auth_handler)
):
    """Request password reset"""
    return await auth_handler.request_password_reset(reset_data)


@auth_router.post("/password-reset")
async def reset_password(reset_data: PasswordResetDTO, auth_handler: AuthHandler = Depends(get_auth_handler)):
    """Reset password with token"""
    return await auth_handler.reset_password(reset_data)


@auth_router.post("/verify-email")
async def verify_email(
    verification_data: EmailVerificationDTO, auth_handler: AuthHandler = Depends(get_auth_handler)
):
    """Verify user email with OTP"""
    return await auth_handler.verify_email(verification_data)

@auth_router.get("/google/callback")
async def google_callback(request: Request, auth_handler: AuthHandler = Depends(get_auth_handler)):
    """Handle Google OAuth callback"""
    code = request.query_params.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="No code received from Google")
    
    tokens = await auth_handler.handle_google_callback(code)
    return tokens