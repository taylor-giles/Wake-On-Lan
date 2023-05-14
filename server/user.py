'''
    User handling code, along with authentication
'''

from datetime import timedelta, datetime
from pydantic import BaseModel
from wol import ClientModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, Depends, status
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer
from logger import logger as LOGGER
from config import JWT


class UserExistsException(Exception):
    pass


class BareUserModel(BaseModel):
    ''' The user model we would be ok showing the users '''
    id: str
    username: str
    clients: list[ClientModel]
    disabled: bool


class UserModel(BareUserModel):
    ''' The user model we would see in the database '''
    hashed_password: str



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


def get_user(username: str):
    if username in fake_db:
        user_dict = fake_db[username]
        return UserModel(**user_dict)


def insert_user(username:str, password: str):
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


def create_access_token(user: UserModel):
    to_encode = {
        'sub': user.username,
        'exp': datetime.utcnow() + timedelta(minutes=JWT.access_token_expires_minutes)
    }

    encoded_jwt = jwt.encode(to_encode, JWT.secret_key, algorithm=JWT.algorithm)

    return { "access_token": encoded_jwt, "token_type": "bearer" }


def authenticate_user(username: str, password: str):
    user = get_user(username)

    if not user and not verify_password(password, user.hashed_password):
        return False

    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, JWT.secret_key, algorithms=[JWT.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception

    user = get_user(username=token_data.username)

    if user is None:
        raise credentials_exception

    return user


async def get_current_active_user(current_user: Annotated[UserModel, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


AUTHENTICATED_USER = Annotated[UserModel, Depends(get_current_active_user)]
''' Use this with fastapi endpoints to get the current logged in user '''