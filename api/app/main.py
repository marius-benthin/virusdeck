import redis
import logging
from typing import Dict
from pydantic import BaseModel
from datetime import timezone
import sqlalchemy as db
from sqlalchemy.orm import sessionmaker
from configparser import ConfigParser
from fastapi import FastAPI, Request, Path
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, BigInteger, String, Boolean, DateTime, ForeignKey, exc
from sqlalchemy.dialects.mysql import TEXT


Base = declarative_base()


class TableUser(Base):
    __tablename__ = 'twitter_users'

    id = Column(BigInteger, primary_key=True)
    name = Column(String(50))
    screen_name = Column(String(15), index=True)
    protected = Column(Boolean)
    verified = Column(Boolean)
    created_at = Column(DateTime)
    profile_image_url_https = Column(TEXT, nullable=True, default=None)


class TableTweet(Base):
    __tablename__ = 'twitter_tweets'

    id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey(TableUser.id))
    created_at = Column(DateTime)
    text = Column(TEXT)
    source = Column(TEXT)
    truncated = Column(Boolean)
    in_reply_to_user_id = Column(BigInteger, nullable=True, default=None)
    in_reply_to_status_id = Column(BigInteger, nullable=True, default=None)
    in_reply_to_screen_name = Column(TEXT, nullable=True, default=None)
    possibly_sensitive = Column(Boolean)
    lang = Column(TEXT)


logging.info("Reading configuration files ...")
cfg = ConfigParser()
cfg.read(['secrets.ini', '../secrets.ini', '../../secrets.ini'])

redis_url: str = cfg.get("redis", "url")

mysql_url: str = cfg.get("mysql", "url")

api_title: str = cfg.get("api", "title")
api_description: str = cfg.get("api", "description")
api_version: str = cfg.get("api", "version")
api_url: str = cfg.get("api", "url")

dashboard_url: str = cfg.get("dashboard", "url")

redis = redis.from_url(redis_url)

engine = db.create_engine(mysql_url, pool_pre_ping=True, pool_recycle=True)
Base.metadata.create_all(engine)

app = FastAPI(title=api_title, description=api_description, version=api_version, docs_url='/')
app.add_middleware(CORSMiddleware, allow_origins=[dashboard_url], allow_methods=["*"], allow_headers=["*"])


def get_file_hash(file_hash: str):
    file_hash = file_hash.lower()
    return {
            "bazaar": redis.getbit(file_hash, 0),
            "urlhaus": redis.getbit(file_hash, 1),
            "virusshare": redis.getbit(file_hash, 2),
            "vx-underground": redis.getbit(file_hash, 3),
            "malshare": redis.getbit(file_hash, 4),
            "hybrid-analysis": redis.getbit(file_hash, 5),
            "threatfox": redis.getbit(file_hash, 6)
    }


class Telegram(BaseModel):
    update_id: int
    message: Dict


@app.post("/telegram/webhook", include_in_schema=False)
async def telegram_webhook(request: Request):
    data = await request.body()
    print("Telegram: %s" % data)
    return {"success": True}


@app.get("/sources/md5/{md5}", description="Returns a list of sources that own this sample.", tags=["Sources"])
async def sources(md5: str = Path(None, regex="^[a-fA-F0-9]{32}$")):
    if md5 is not None:
        return get_file_hash(file_hash=md5)


@app.get("/sources/sha256/{sha256}", description="Returns a list of sources that own this sample.", tags=["Sources"])
async def sources(sha256: str = Path(None, regex="^[a-fA-F0-9]{64}$")):
    if sha256 is not None:
        return get_file_hash(file_hash=sha256)


@app.get("/twitter/user_ids", description="Returns a list of tracked Twitter user IDs.", tags=["Twitter"])
async def twitter_users():
    return redis.smembers("twitter_users")


@app.get("/twitter/keywords", description="Returns a list of tracked Twitter keywords.", tags=["Twitter"])
async def twitter_keywords():
    return redis.smembers("twitter_keywords")


@app.get("/twitter/tweets", description="Returns a list of recent Tweets with known malware hashes.", tags=["Twitter"])
async def twitter_tweets():
    results = []
    try:
        session = sessionmaker(bind=engine, autocommit=True)()
        rows = session.query(TableTweet.created_at, TableTweet.id, TableTweet.text, TableTweet.lang,
                             TableUser.name, TableUser.screen_name, TableUser.profile_image_url_https)\
            .filter(TableTweet.user_id == TableUser.id)\
            .order_by(TableTweet.created_at.desc())\
            .limit(1000)
        for row in rows:
            result = row._asdict()
            result["created_at"] = result["created_at"].replace(tzinfo=timezone.utc)
            result["id"] = str(result["id"])
            results.append(result)
    except exc.SQLAlchemyError as e:
        logging.error(e)
    return results
