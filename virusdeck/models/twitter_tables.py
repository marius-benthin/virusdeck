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
    is_bot = Column(Boolean)
    is_trustable = Column(Boolean)


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


class TableHashes(Base):
    __tablename__ = 'file_hashes'

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    sha256 = Column(String(64), index=True, unique=True)
    md5 = Column(String(32), index=True)
    filesize = Column(BigInteger, nullable=True)
    filetype = Column(TEXT, nullable=True)
    ssdeep = Column(TEXT, nullable=True)
    imphash = Column(TEXT, nullable=True)
    signatures = Column(TEXT, nullable=True, default=None)
