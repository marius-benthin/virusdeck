import yaml
from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from virusdeck.web.routers import api, dashboard

# read configuration yaml file
with open("configs.yml", "r") as file:
    config: dict = yaml.safe_load(file)
    virusdeck_url: str = config["virusdeck"]["url"]
    virusdeck_title: str = config["virusdeck"]["title"]
    virusdeck_version: str = config["virusdeck"]["version"]
    virusdeck_description: str = config["virusdeck"]["description"]

# read secrets yaml file
with open(config["secrets"], "r") as file:
    secrets: dict = yaml.safe_load(file)

app = FastAPI(title=virusdeck_title, description=virusdeck_description, version=virusdeck_version)
app.include_router(api.router)
app.include_router(dashboard.router)


@app.get("/")
async def root():
    return RedirectResponse('/dashboard')
