'''
    Oauth Authentication
'''


from config import JWT, DB
from typing import Annotated
from jose import JWTError, jwt
from models.auth import TokenData
from urllib.request import Request
from models.users import UserModel
from logger import logger as LOGGER
from datetime import timedelta, datetime
from fastapi.security import OAuth2PasswordBearer
from fastapi import HTTPException, Depends, status, Request


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/login")


def create_access_token(username):
    to_encode = {
        'sub': username,
        'exp': datetime.utcnow() + timedelta(minutes=JWT.access_token_expires_minutes)
    }
    encoded_jwt = jwt.encode(to_encode, JWT.secret_key, algorithm=JWT.algorithm)

    return { "access_token": encoded_jwt, "token_type": "bearer" }


async def get_current_user(request: Request, token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={ "WWW-Authenticate": "Bearer" },
    )

    try:
        payload = jwt.decode(token, JWT.secret_key, algorithms=[JWT.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception

    # Get the user from the database
    user = request.app.database[DB.user_collection].find_one(
        { 'username': token_data.username }
    )

    if user is None:
        raise credentials_exception

    user = UserModel(**user)

    return user


async def get_current_active_user(current_user: Annotated[UserModel, Depends(get_current_user)]):
    if current_user.disabled:
        LOGGER.warning(f'{current_user.username} is disabled, and attempted to login')
        raise HTTPException(status_code=400, detail="Inactive user")

    return current_user


CURRENT_AUTHENTICATED_USER = Annotated[UserModel, Depends(get_current_active_user)]
''' Use this with fastapi endpoints to get the current logged in user '''
