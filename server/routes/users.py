from tools.config import DB
from typing import Annotated
from models.auth import Token
from pydantic import BaseModel, validator
from tools.logger import logger as LOGGER
from fastapi.encoders import jsonable_encoder
from models.users import BareUserModel, UserModel
from fastapi.security import OAuth2PasswordRequestForm
from auth.password import verify_password, hash_password
from auth.oauth import create_access_token, CURRENT_AUTHENTICATED_USER
from fastapi import APIRouter, Depends, Response, Request, HTTPException, status


# /users Router
router = APIRouter()


@router.post('/login', response_model=Token)
async def login_for_access_token(request: Request, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    ''' Login user and respond with an OAUTH Token '''
    LOGGER.info(f'Logging in user {form_data.username}')

    # Get the user from the database
    user = request.app.database[DB.user_collection].find_one(
        { 'username': form_data.username }
    )

    if user:
        user = UserModel(**user)

    # Check the password
    if not user or not verify_password(form_data.password, user.hashed_password):
        LOGGER.info(f'User failed to login')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={ "WWW-Authenticate": "Bearer" },
        )

    access_token = create_access_token(user.username)
    LOGGER.info(f'User {user.username } logged in!')
    return access_token


# NOTE: We are using stateless authentication, meaning that there is no logout function.
#   The user is simply logged out once their token expires
#   In the future, we can implement refresh tokens: https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/


@router.get('/me', response_model=BareUserModel)
async def get_me(request: Request, current_user: CURRENT_AUTHENTICATED_USER):
    ''' Get the current logged in user '''

    LOGGER.info(request.headers)

    return current_user


class CreateUserBody(BaseModel):
    username: str
    password: str

    @validator('password')
    def validate_password(cls, v):
        assert len(v) > 4, 'Password must be more than 4 characters'
        return v


@router.post('/create', response_model=BareUserModel)
async def create_user(request: Request, response: Response, body: CreateUserBody):
    ''' Create a new user '''
    LOGGER.info(f'Creating a new user with username {body.username}')


    # Verify the username does not exist already
    duplicate = request.app.database[DB.user_collection].find_one(
        { 'username': body.username }
    )

    if duplicate:
        LOGGER.info(f'Duplicate username {body.username} found')
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        )

    # Create the new user
    user = UserModel(
        username=body.username,
        clients=[],
        disabled=False,
        hashed_password=hash_password(body.password)
    )

    user = jsonable_encoder(user)
    new_user = request.app.database[DB.user_collection].insert_one(user)
    created_user = request.app.database[DB.user_collection].find_one(
        { '_id': new_user.inserted_id }
    )

    LOGGER.info(f'User created: {created_user}')

    return created_user
