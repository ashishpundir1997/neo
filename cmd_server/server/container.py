from typing import Any
from fastapi import HTTPException
from dependency_injector import containers, providers
from dotenv import load_dotenv
from omegaconf import DictConfig, OmegaConf

from pkg.log.logger import Logger
from pkg.db_util.postgres_conn import PostgresConnection
from pkg.db_util.types import PostgresConfig
from pkg.redis.client import RedisClient
from pkg.auth_token_client.client import TokenClient
from pkg.db_util.sql_alchemy.initializer import DatabaseInitializer
from app.user.repository.user_repository import UserRepository
from app.user.service.user_service import UserService
from app.auth.service.auth_service import AuthService
from app.auth.api.handlers import AuthHandler
from conf.config import AppConfig
from pkg.smtp_client.client import EmailClient, EmailConfig   


# Load .env before using OmegaConf
load_dotenv()


class Container(containers.DeclarativeContainer):
    """Main DI Container."""

    # Config provider
    config = providers.Configuration()

    # Logger
    logger = providers.Singleton(Logger, name="projectneo")

    # Postgres database config & connection
    postgres_config = providers.Singleton(
        PostgresConfig,
        host=config.postgres.host,
        port=config.postgres.port,
        username=config.postgres.user,
        password=config.postgres.password,
        database=config.postgres.database,
        pool_size=config.postgres.pool_size,
        max_overflow=config.postgres.max_overflow,
        pool_timeout=config.postgres.pool_timeout,
        pool_recycle=config.postgres.pool_recycle,
    )

    postgres_conn = providers.Singleton(
        PostgresConnection,
        db_config=postgres_config,
        logger=logger,
    )

    # Factory for making async DB sessions
    postgres_session_factory = providers.Callable(
    postgres_conn.provided.get_session
)

    # Database initializer (e.g. for migrations/startup tasks)
    db_initializer = providers.Singleton(
        DatabaseInitializer,
        postgres_conn=postgres_conn,
        logger=logger,
    )

    # Redis client
    redis_client = providers.Singleton(
        RedisClient,
        host=config.redis.host,
        port=config.redis.port,
        password=config.redis.password,
        logger=logger,
    )

    # Token client
    token_client = providers.Singleton(
        TokenClient,
        secret_key=config.jwt_auth.super_secret_key,
        refresh_secret_key=config.jwt_auth.refresh_secret_key,
        leeway_seconds=10,
    )

    # Email config
    email_config = providers.Singleton(
        EmailConfig,
        smtp_server=config.smtp.smtp_server,
        smtp_port=config.smtp.smtp_port,
        username=config.smtp.username,
        password=config.smtp.password,
        use_tls=config.smtp.use_tls,
        max_retries=config.smtp.max_retries,
    )
    
    # Email client provider
    email_client = providers.Singleton(
        EmailClient,
        config=email_config,
    )

    # Repositories
    user_repository = providers.Singleton(
        UserRepository,
        db_session_factory=postgres_conn.provided.get_session,
        logger=logger,
    )

    # Services
    user_service = providers.Singleton(
        UserService,
        user_repository=user_repository,
        logger=logger,
        token_client=token_client,
    )

    auth_service = providers.Singleton(
        AuthService,
        user_service=user_service,
        token_client=token_client,
        redis_client=redis_client,
        logger=logger,
        smtp_client=email_client,
    )

    # API handlers
    auth_handler = providers.Singleton(
        AuthHandler, auth_service=auth_service, logger=logger
    )
    
    



# Factory method to create container with loaded config
def create_container(cfg: DictConfig) -> Container:
    """Create and configure the DI container."""
    container_obj = Container()

    schema = OmegaConf.structured(AppConfig)
    merged_config = OmegaConf.merge(schema, cfg)
    config_dict = OmegaConf.to_container(merged_config, resolve=True)

    container_obj.config.from_dict(config_dict)  # type: ignore

    return container_obj


if __name__ == "__main__":
    container = create_container(cfg=OmegaConf.load("../../conf/config.yaml"))  # type: ignore
