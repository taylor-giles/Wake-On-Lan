from wsgiref.validate import validator
import jwt
import bcrypt
import logging
import configparser
from time import perf_counter
from pydantic import BaseModel
from typing import Annotated
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from logger import logger as LOGGER, rychlyLogFormatter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm


LOGGER.info('Starting Wake on LAN Server')

config = configparser.ConfigParser(default_section='ENV')
config.read('configs/prod.ini')

# Read the parameters
secret = config['ENV'].get('secret')
algorithm = config['ENV'].get('algorithm')
expires_minutes = config['ENV'].get('expires_minutes')

allow_origins = config['CORS'].get('allow_origins').split(',')
allow_credentials = config['CORS'].getboolean('allow_credentials')
allow_methods = config['CORS'].get('allow_methods').split(',')
allow_headers = config['CORS'].get('allow_headers').split(',')

LOGGER.info(f'...... Parameter secret: {secret}')
LOGGER.info(f'...... Parameter algorithm: {algorithm}')
LOGGER.info(f'...... Parameter expires_minutes: {expires_minutes}')

LOGGER.info(f'...... Parameter allow_origins: {allow_origins}')
LOGGER.info(f'...... Parameter allow_credentials: {allow_credentials}')
LOGGER.info(f'...... Parameter allow_methods: {allow_methods}')
LOGGER.info(f'...... Parameter allow_headers: {allow_headers}')


class ComputerModel(BaseModel):
    id: str
    name: str
    group: str
    mac_address: str


class ClientModel(BaseModel):
    id: str
    name: str
    computers: list[ComputerModel]


class UserModel(BaseModel):
    id: str
    username: str
    hashed_password: str
    clients: list[ClientModel]


# ------------------------ ~ Authentication ~ ------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def hash_password(password):
    bytes = password.encode('utf-8')
    salt = bcrypt.getsalt()
    hash = bcrypt.hashpw(bytes, salt)
    return hash


def confirm_password(hash, password):
    bytes = password.encode('utf-8')
    check = bcrypt.checkpw(bytes, hash)
    return check


app = FastAPI()


app.add_middleware(
   CORSMiddleware,
    allow_origins = allow_origins,
    allow_credentials =allow_credentials,
    allow_methods = allow_methods,
    allow_headers= allow_headers,
)


@app.on_event('startup')
async def startup_event():
    loggers = [ logging.getLogger("uvicorn"), logging.getLogger("uvicorn.access") ]
    
    for _logger in loggers:
        _logger.handlers[0].setFormatter(rychlyLogFormatter)
        
    loggers[0].info("Initialized logger")


@app.middleware('http')
async def log_requests_middleware(request: Request, call_next):
    interval = perf_counter()
    response = await call_next(request)
    interval = perf_counter() - interval
    response.headers['X-Process-time'] = f'{interval:0.12f} seconds'
    LOGGER.info(f"{request.client[0]}:{request.client[1]} - \"{request.method} {request.url.path}\" completed in {interval:0.12f} seconds")
    return response


# https://fastapi.tiangolo.com/tutorial/security/simple-oauth2/#__tabbed_1_1
# @app.post("/token")
# async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
#     user_dict = fake_users_db.get(form_data.username)
#     if not user_dict:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
#     user = UserInDB(**user_dict)
#     hashed_password = fake_hash_password(form_data.password)
#     if not hashed_password == user.hashed_password:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")

#     return {"access_token": user.username, "token_type": "bearer"}


class LoginModel(BaseModel):
    username: str
    password: str


@app.post('/user/login')
async def user_login(login_model: LoginModel) -> list[ClientModel]:
    pass










@app.post('/user/create')
async def create_user():
    ''' Create a user '''
    return { "message": "Create user" }





@app.post('/wol/{client_id}/{computer_id}')
async def wake_on_lan(response: Response, client_id: str, computer_id: str):
    ''' Send the wake on lan command '''
    pass
