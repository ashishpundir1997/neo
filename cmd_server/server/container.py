import os
from app.auth.api.handlers import AuthHandler
from app.auth.service.auth_service import AuthService
from omegaconf import DictConfig, OmegaConf
from app.user.repository.user_repository import UserRepository
from app.user.service.user_service import UserService
from dependency_injector import containers, providers
from pkg.auth_token_client.client import TokenClient
from pkg.db_util.postgres_conn import PostgresConnection
from pkg.db_util.types import DatabaseConfig, PostgresConfig
from conf.config import AppConfig
from pkg.log.logger import Logger
from pkg.redis.client import RedisClient
from pkg.db_util.sql_alchemy.initializer import DatabaseInitializer

class Container(containers.DeclarativeContainer):
    config = providers.Configuration()

   
    logger = providers.Singleton(Logger)


    postgres_config = providers.Singleton(PostgresConfig,
                                          host=config.postgres.host,
                                          port=config.postgres.port,
                                          username=config.postgres.user,
                                          password=config.postgres.password,
                                          database=config.postgres.database)
    postgres_conn = providers.Singleton(PostgresConnection, db_config=postgres_config, logger=logger)
    db_initializer = providers.Singleton(
        DatabaseInitializer,
        postgres_conn=postgres_conn,
        logger=logger
    )

    redis_client = providers.Singleton(
        RedisClient,
        host=config.redis.host,
        port=config.redis.port,
        password=config.redis.password,
        logger=logger
    )

    token_client = providers.Singleton(
        TokenClient,
        secret_key=config.jwt_auth.super_secret_key,
        refresh_secret_key=config.jwt_auth.refresh_secret_key,
    )

    user_repository = providers.Singleton(
        UserRepository,
        db_conn=postgres_conn,
        logger=logger,
    )
    

    user_service = providers.Singleton(
        UserService,
        user_repository=user_repository,
        logger=logger,
        token_client=token_client,
    )
 
    auth_service = providers.Singleton(
        AuthService,
        user_service=user_service,
        redis_client=redis_client,
        logger=logger,
    )

    auth_handler = providers.Singleton(
        AuthHandler, auth_service=auth_service, logger=logger
    )

    # token_client = providers.Singleton(
    #     TokenClient,
    #     secret_key=config.jwt_auth.super_secret_key,
    #     refresh_secret_key=config.jwt_auth.refresh_secret_key,
    # )
    # tokens_repository = providers.Singleton(
    #     sql_db_conn=postgres_conn,
    #     logger=logger,
    # )



    # redis_client = providers.Singleton(
    #     host=config.redis.host,
    #     port=config.redis.port,
    #     password=config.redis.password,
    #     logger=logger
    # )
    
  
    
   


def create_container(cfg: DictConfig) -> Container:
    """Create and configure the dependency injection container."""
    container_obj = Container()

    # Create structured config with defaults
    schema = OmegaConf.structured(AppConfig)

    # Merge with provided config
    config = OmegaConf.merge(schema, cfg)

    # Convert to dict and resolve interpolations
    config_dict = OmegaConf.to_container(config, resolve=True)

    # Update container config
    container_obj.config.from_dict(config_dict)  # type: ignore

    return container_obj


if __name__ == "__main__":
    container = create_container(cfg=OmegaConf.load("../../conf/config.yaml"))  # type: ignore
