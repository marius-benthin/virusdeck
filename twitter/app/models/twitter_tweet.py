from datetime import datetime
from typing import List
from pydantic import BaseModel, validator

# Format: Sat Oct 03 16:03:41 +0000 2020
date_format = "%a %b %d %H:%M:%S %z %Y"


class User(BaseModel):
    """
    User of Tweet
    """
    id: int
    id_str: str
    name: str
    screen_name: str
    location: str = None
    url: str = None
    description: str = None
    protected: bool
    verified: bool
    followers_count: int
    friends_count: int
    listed_count: int
    favourites_count: int
    statuses_count: int
    created_at: datetime
    profile_image_url_https: str = None
    profile_banner_url: str = None
    default_profile: bool = None
    default_profile_image: bool = None
    withheld_in_countries: List[str] = None
    withheld_scope: str = None

    @validator("created_at", pre=True)
    def datetime_validate(cls, created_at):
        return datetime.strptime(created_at, date_format)


class Hashtag(BaseModel):
    """
    Hashtag in Tweet
    """
    text: str
    indices: List[int]


class Media(BaseModel):
    """
    Media in Tweet
    """
    display_url: str
    expanded_url: str
    id: int
    id_str: str
    indices: List[int]
    media_url: str
    media_url_https: str
    sizes: dict
    type: str
    url: str


class Url(BaseModel):
    """
    URL in Tweet
    """
    url: str
    expanded_url: str
    display_url: str
    indices: List[int]


class UserMention(BaseModel):
    """
    User mention in Tweet
    """
    name: str = None
    indices: List[int]
    screen_name: str
    id: int = None
    id_str: str = None


class Symbol(BaseModel):
    """
    Symbol in Tweet
    """
    text: str
    indices: List[int]


class Option(BaseModel):
    """
    Option in Poll
    """
    position: int
    text: str


class Poll(BaseModel):
    """
    Poll in Tweet
    """
    options: List[Option]
    end_datetime: datetime
    duration_minutes: int

    @validator("end_datetime", pre=True)
    def datetime_validate(cls, end_datetime):
        return datetime.strptime(end_datetime, date_format)


class Entities(BaseModel):
    """
    Entities in Tweet
    """
    hashtags: List[Hashtag] = []
    media: List[Media] = []
    urls: List[Url] = []
    user_mentions: List[UserMention] = []
    symbols: List[Symbol] = []
    polls: List[Poll] = []


class Geo(BaseModel):
    """
    Geo in Tweet
    """
    type: str
    coordinates: List[int]


class Coordinate(BaseModel):
    """
    Coordinate in Tweet
    """
    type: str
    coordinates: List[int]


class BoundingBox(BaseModel):
    """
    BoundingBox in Place
    """
    type: str
    coordinates: List[List[List[int]]]


class Place(BaseModel):
    """
    Place in Tweet
    """
    id: str
    url: str
    place_type: str
    name: str
    full_name: str
    country_code: str
    country: str
    attributes: dict


class ExtendedTweet(BaseModel):
    """
    Extended Tweet
    """
    full_text: str
    display_text_range: List[int]
    entities: Entities


class Tweet(BaseModel):
    """
    Basic Tweet
    """
    created_at: datetime
    id: int
    id_str: str
    text: str
    source: str
    truncated: bool
    in_reply_to_status_id: int = None
    in_reply_to_status_id_str: str = None
    in_reply_to_user_id: int = None
    in_reply_to_user_id_str: str = None
    in_reply_to_screen_name: str = None
    user: User
    geo: Geo = None
    coordinates: Coordinate = None
    place: Place = None
    contributors: str = None
    quoted_status_id: int = None
    quoted_status_id_str: str = None
    is_quote_status: bool
    quoted_status: dict = None
    retweeted_status: dict = None
    extended_tweet: ExtendedTweet = None
    quote_count: int
    reply_count: int
    retweet_count: int
    favorite_count: int = None
    entities: Entities
    extended_entities: Entities = None
    favorited: bool
    retweeted: bool
    possibly_sensitive: bool = False
    filter_level: str
    lang: str
    timestamp_ms: str = None

    @validator("created_at", pre=True)
    def datetime_validate(cls, created_at):
        return datetime.strptime(created_at, date_format)
