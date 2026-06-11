from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from v2.config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Enable SQLite Write-Ahead Logging (WAL) on connection
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_v2_db():
    Base.metadata.create_all(bind=engine)

def get_v2_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
