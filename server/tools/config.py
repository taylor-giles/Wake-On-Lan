__all__ = ['ENV', 'JWT', 'CORS', 'DB']


import configparser
from tools.logger import logger as LOGGER


config = configparser.ConfigParser()
config.read('configs/prod.ini')


for section_name, section_data in config.items():
    for key, val in section_data.items():
        LOGGER.info(f'...... Parameter {section_name} <{key}>: {val}')


class ENV:
    name = config['ENV'].get('name')
    author = config['ENV'].get('author')


class CORS:
    ''' CORS Related Fields '''
    allow_origins = config['CORS'].get('allow_origins').split(',')
    allow_credentials = config['CORS'].getboolean('allow_credentials')
    allow_methods = config['CORS'].get('allow_methods').split(',')
    allow_headers = config['CORS'].get('allow_headers').split(',')


class JWT:
    ''' Environment Related Fields '''
    secret_key = config['JWT'].get('secret')
    algorithm = config['JWT'].get('algorithm')
    access_token_expires_minutes = config['JWT'].getint('expires_minutes')


class DB:
    ''' Mongodb fields '''
    uri = config['DB'].get('connection_uri')
    name = config['DB'].get('name')
    user_collection = config['DB'].get('user_collection')
    client_collection = config['DB'].get('client_collection')