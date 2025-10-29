from app.auth.api.handlers import AuthHandler
from app.auth.service.auth_service import AuthService
from app.user.service.user_service import UserService
from pkg.auth_token_client.client import TokenClient
from pkg.redis.redis_client import RedisClient
from pkg.log.logger import Logger
from app.user.repository.user_repository import UserRepository
import os


def get_auth_handler() -> AuthHandler:
    logger = Logger("auth")

    jwt_secret_key = os.getenv("JWT_SUPER_SECRET")
    jwt_refresh_secret_key = os.getenv("JWT_REFRESH_SECRET")

    token_client = TokenClient(
        secret_key=jwt_secret_key,
        refresh_secret_key=jwt_refresh_secret_key
    )
    redis_client = RedisClient() 
    user_repository = UserRepository()  
    user_service = UserService(
        user_repository=user_repository,
        logger=logger,
        token_client=token_client
    )

    auth_service = AuthService(
        user_service=user_service,
        token_client=token_client,
        redis_client=redis_client,
        google_oauth_client_id="dummy",
        apple_oauth_client_id="dummy",
        logger=logger,
    )

    return AuthHandler(auth_service=auth_service, logger=logger)


