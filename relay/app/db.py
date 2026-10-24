from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os

DATABASE_URL = os.getenv("RELAY_DATABASE_URL", "postgresql+psycopg2://mystere:devpassword@localhost:5432/mystere_relay")
DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
