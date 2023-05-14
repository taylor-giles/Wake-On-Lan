from pydantic import BaseModel


class ComputerModel(BaseModel):
    id: str
    name: str
    group: str
    mac_address: str


class ClientModel(BaseModel):
    id: str
    name: str
    computers: list[ComputerModel]
