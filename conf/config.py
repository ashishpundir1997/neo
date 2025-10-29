# pkg/config/config.py

from dataclasses import dataclass, field
from typing import List, Optional



@dataclass
class JWTAuthConfig:
    super_secret_key: str
    refresh_secret_key: str



@dataclass
class RedisConfig:
    host: str
    port: str
    password: str


@dataclass
class PostgresConfig:
    host: str
    port: int
    database: str
    user: str
    password: str




@dataclass
class AppConfig:

    jwt_auth: JWTAuthConfig

    redis: RedisConfig
   
    postgres: PostgresConfig


