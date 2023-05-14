from dis import dis
from jose import JWTError, jwt
from passlib.context import CryptContext
import logging
import configparser
from time import perf_counter
from datetime import datetime, timedelta
from pydantic import BaseModel, validator
from typing import Annotated
from fastapi import FastAPI, Request, Response, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from logger import logger as LOGGER, rychlyLogFormatter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm


LOGGER.info('Starting Wake on LAN Server')

config = configparser.ConfigParser(default_section='ENV')
config.read('configs/prod.ini')

# Read the parameters
SECRET_KEY = config['ENV'].get('secret')
ALGORITHM = config['ENV'].get('algorithm')
ACCESS_TOKEN_EXPIRE_MINUTES = config['ENV'].getint('expires_minutes')

allow_origins = config['CORS'].get('allow_origins').split(',')
allow_credentials = config['CORS'].getboolean('allow_credentials')
allow_methods = config['CORS'].get('allow_methods').split(',')
allow_headers = config['CORS'].get('allow_headers').split(',')

LOGGER.info(f'...... Parameter secret: {SECRET_KEY}')
LOGGER.info(f'...... Parameter algorithm: {ALGORITHM}')
LOGGER.info(f'...... Parameter expires_minutes: {ACCESS_TOKEN_EXPIRE_MINUTES}')

LOGGER.info(f'...... Parameter allow_origins: {allow_origins}')
LOGGER.info(f'...... Parameter allow_credentials: {allow_credentials}')
LOGGER.info(f'...... Parameter allow_methods: {allow_methods}')
LOGGER.info(f'...... Parameter allow_headers: {allow_headers}')


class UserExistsException(Exception):
    pass


class ComputerModel(BaseModel):
    id: str
    name: str
    group: str
    mac_address: str


class ClientModel(BaseModel):
    id: str
    name: str
    computers: list[ComputerModel]


class BareUserModel(BaseModel):
    ''' The user model we would be ok showing the users '''
    id: str
    username: str
    clients: list[ClientModel]
    disabled: bool


class UserModel(BareUserModel):
    ''' The user model we would see in the database '''
    hashed_password: str


# ------------------------ ~ Database Interaction ~ ------------------------

id_counter = 1

fake_db = {
    'shadow_badow': {
        'id': 0,
        'username': 'shadow_badow',
        'clients': [],
        'hashed_password': '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW',
        'disabled': False
    }
}


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserModel(**user_dict)


def insert_user(db, username:str, password: str):
    global id_counter

    id = id_counter
    hashed_password = hash_password(password)
    disabled = False

    if username in fake_db:
        raise UserExistsException(f'User {username} already exists in the database')

    id_counter += 1

    # Validate the user
    validated_user = UserModel(id=id, username=username, hashed_password=hashed_password, disabled=disabled, clients=[])

    # Insert the user
    fake_db[username] = validated_user.dict()

    LOGGER.info(f'Inserting user {fake_db[username]} into the database')


# ------------------------ ~ Authentication ~ ------------------------


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/login")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: Annotated[UserModel, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# ------------------------ ~ API ~ ------------------------


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


@app.post("/users/login", tags=['Users'], response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(fake_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={ "sub": user.username }, expires_delta=access_token_expires
    )
    LOGGER.info(f'Logged in user, {user.username}')    
    return { "access_token": access_token, "token_type": "bearer" }


@app.get("/users/me", tags=['Users'], response_model=BareUserModel)
async def get_me(current_user: Annotated[UserModel, Depends(get_current_active_user)]):
    ''' Get the current logged in user '''
    
    return current_user


class CreateUserBody(BaseModel):
    username: str
    password: str

    @validator('password')
    def validate_password(cls, v):
        assert len(v) > 4, 'Password must be more than 4 characters'
        return v


@app.post('/users/create', tags=['Users'], response_model=BareUserModel)
async def create_user(response: Response, body: CreateUserBody):
    ''' Create a new user '''

    username = body.username
    password = body.password  
    insert_user(fake_db, username, password)

    new_user = get_user(fake_db, username)

    return new_user


@app.post('/wol/{client_id}/{computer_id}', tags=['Wake On Lan'])
async def wake_on_lan(
    response: Response, 
    current_user: Annotated[UserModel, Depends(get_current_active_user)],
    client_id: str, 
    computer_id: str
):
    ''' Send the wake on lan command '''
    
    return {
        'client_id': client_id,
        'computer_id': computer_id,
        'message': 'WOL!'
    }


