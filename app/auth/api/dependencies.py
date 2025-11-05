from typing import Annotated, Optional
from fastapi import Depends, Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.auth.api.handlers import AuthHandler
from app.auth.service.auth_service import AuthService
from pkg.log.logger import Logger


# HTTP Bearer token security scheme
security = HTTPBearer(auto_error=False)


def get_auth_handler(request: Request) -> AuthHandler:
    """Get auth handler from container"""
    return request.app.state.container.auth_handler()


def get_auth_service(request: Request) -> AuthService:
    """Get auth service from container"""
    return request.app.state.container.auth_service()


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> dict:
    """
    Dependency to get current authenticated user from JWT token.
    
    Usage:
        @router.get("/protected")
        async def protected_route(current_user: dict = Depends(get_current_user)):
            user_id = current_user["user_id"]
            ...
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        auth_service = get_auth_service(request)
        token = credentials.credentials
        payload = await auth_service.verify_token(token)
        return payload
    except HTTPException as e:
        raise e
    except Exception as e:
        logger = request.app.state.container.logger()
        logger.error(f"Error authenticating user: {e!s}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_optional_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[dict]:
    """
    Dependency to optionally get current user (for routes that work with or without auth).
    Returns None if no token provided or token is invalid.
    """
    if not credentials:
        return None
    
    try:
        auth_service = get_auth_service(request)
        token = credentials.credentials
        payload = await auth_service.verify_token(token)
        return payload
    except (HTTPException, Exception):
        return None


# Type aliases for cleaner dependency injection
AuthHandlerDep = Annotated[AuthHandler, Depends(get_auth_handler)]
CurrentUserDep = Annotated[dict, Depends(get_current_user)]
OptionalCurrentUserDep = Annotated[Optional[dict], Depends(get_optional_current_user)]
