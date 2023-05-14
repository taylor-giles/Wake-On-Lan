from time import perf_counter
from pymongo import MongoClient
from config import ENV, CORS, DB
from logger import logger as LOGGER
from fastapi import FastAPI, Request
from routes.users import router as users_router
from fastapi.middleware.cors import CORSMiddleware

LOGGER.info(f'Starting {ENV.name} Server')
LOGGER.info(f'Author: {ENV.author}')


app = FastAPI()


app.add_middleware(
   CORSMiddleware,
    allow_origins = CORS.allow_origins,
    allow_credentials =CORS.allow_credentials,
    allow_methods = CORS.allow_methods,
    allow_headers= CORS.allow_headers,
)


@app.on_event('startup')
def startup_db_client():
    app.mongodb_client = MongoClient(DB.uri)
    app.database = app.mongodb_client[DB.name]
    LOGGER.info('Connected to the MongoDB database')


@app.on_event('shutdown')
def shutdown_db_client():
    app.mongodb_client.close()


@app.middleware('http')
async def log_requests_middleware(request: Request, call_next):
    interval = perf_counter()
    response = await call_next(request)
    interval = perf_counter() - interval
    response.headers['X-Process-time'] = f'{interval:0.12f} seconds'
    LOGGER.info(f"{request.client[0]}:{request.client[1]} - \"{request.method} {request.url.path}\" completed in {interval:0.12f} seconds")
    return response


LOGGER.info('Initializing Routes')
app.include_router(users_router, tags=["Users"], prefix="/users")
