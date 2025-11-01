from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
import asyncio

async def check_user():
    engine = create_async_engine(
        "postgresql+asyncpg://ashishpundir:YOUR_PASSWORD@localhost/projectneo"
    )
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT current_user, session_user, current_schema()"))
        rows = result.fetchall()
        print(rows)

asyncio.run(check_user())
