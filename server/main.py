import logging
from config import ENV, CORS
from user import (
    BareUserModel,
    AUTHENTICATED_USER,
    Token,
    authenticate_user,
    create_access_token,
    insert_user,
    get_user,
    UserExistsException
)

from time import perf_counter
from pydantic import BaseModel, validator
from typing import Annotated
from fastapi import FastAPI, Request, Response, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from logger import logger as LOGGER, rychlyLogFormatter
from fastapi.security import OAuth2PasswordRequestForm


LOGGER.info(f'Starting {ENV.name} Server')
LOGGER.info(f'Author: {ENV.author}')


app = FastAPI()


# Setup CORS
app.add_middleware(
   CORSMiddleware,
    allow_origins = CORS.allow_origins,
    allow_credentials =CORS.allow_credentials,
    allow_methods = CORS.allow_methods,
    allow_headers= CORS.allow_headers,
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
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(user)
    LOGGER.info(f'Logged in user, {user.username}')
    return access_token


@app.get("/users/me", tags=['Users'], response_model=BareUserModel)
async def get_me(current_user: AUTHENTICATED_USER):
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

    try:
        insert_user(username, password)

    except UserExistsException:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Conflict, user exists"
        )

    new_user = get_user(username)

    return new_user


@app.post('/wol/{client_id}/{computer_id}', tags=['Wake On Lan'])
async def wake_on_lan(
    response: Response,
    current_user: AUTHENTICATED_USER,
    client_id: str,
    computer_id: str
):
    ''' Send the wake on lan command '''

    return {
        'client_id': client_id,
        'computer_id': computer_id,
        'message': 'WOL!'
    }


