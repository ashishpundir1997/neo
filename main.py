from fastapi import FastAPI
from app.auth.api.routes import auth_router


app = FastAPI()

# ✅ make sure to include your auth routes
app.include_router(auth_router)

@app.get("/")
def home():
    return {"msg": "FastAPI is running 🚀"}
