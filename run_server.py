from server.database import init_db
from server.server import start_server

if __name__ == "__main__":
    init_db()
    start_server()