from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, BigInteger, String, Boolean, DateTime, ForeignKey
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
