# ...existing code...
from fastapi import FastAPI
from omegaconf import OmegaConf
from cmd_server.server.container import create_container
from app.auth.api.routes import auth_router
from dotenv import load_dotenv
load_dotenv()  # This loads environment variables from .env

app = FastAPI()

# create & attach container before handling requests
cfg = OmegaConf.load("conf/config.yaml")  # adjust path if needed
container = create_container(cfg)
app.state.container = container


app.include_router(auth_router)

# optional startup init
@app.on_event("startup")
def on_startup():
    # call initializers if required, e.g. run DB migrations/initializers
    try:
        app.state.container.db_initializer()  # or .db_initializer().run() depending on your provider API
    except Exception:
        pass

# ...existing code to include routers, middleware, etc...