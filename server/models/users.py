import uuid
from models.wol import ClientModel
from pydantic import BaseModel, Field


class BareUserModel(BaseModel):
    ''' The user model we would be ok showing the users '''
    id: str = Field(default_factory=uuid.uuid4, alias="_id")
    username: str
    disabled: bool
    clients: list[ClientModel]


class UserModel(BareUserModel):
    ''' The user model we would see in the database '''
    hashed_password: str

    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "_id": "066de609-b04a-4b30-b46c-32537c7f1f6e",
                "username": "Shadow Badow",
                "clients": [],
                "disabled": False,
                'hashed_password': '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW',
            }
        }