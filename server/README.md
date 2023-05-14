# Wake On Lan Server

The Wake On Lan (WOL) server, is a `FastAPI` application running on a `uvicorn` server.

The server handles interaction with the Mongodb database and also interaction with all clients.

## Starting the server
- Debug Mode: `uvicorn main:app --reload`
- Production Mode: `uvicorn main:app`

## Initializing the server
1. Copy the configs/template.ini file into configs/prod.ini
2. Create a `jwt` secret using `openssl rand -hex 32` and populate the appropriate field in the prod.ini configuration file
3. Adjust CORS parameters
4. Adjust the DB parameters to connect to the mongoDB database
5. With python 3.10, create a new environment ensuring the packages in `requirements.txt` are installed.  If you wish to follow this project's standard, create the environment in `server/.venv`
6. Source the environment
7. Start the server
