from sqlalchemy import create_engine, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# 替換成你自己的連線字串
#DATABASE_URL = "postgresql://main_z378_user:nSpZ4S5IlPt16a4bb7oZCeOZsoaOaAcM@dpg-d207mb6mcj7s73aqsvg0-a.singapore-postgres.render.com:5432/main_z378"
#DATABASE_URL = "postgresql://main_z378_user:nSpZ4S5IlPt16a4bb7oZCeOZsoaOaAcM@dpg-d207mb6mcj7s73aqsvg0-a/main_z378"
DATABASE_URL = "postgresql://main_z378_user:nSpZ4S5IlPt16a4bb7oZCeOZsoaOaAcM@dpg-d207mb6mcj7s73aqsvg0-a.singapore-postgres.render.com:5432/main_z378"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
