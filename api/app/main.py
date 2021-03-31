import re
import json
import redis
import logging
import requests
from typing import Dict, Any
from datetime import timezone
from pydantic import BaseModel
from http.client import responses
from configparser import ConfigParser
from fastapi import FastAPI, Request, Path
from fastapi.middleware.cors import CORSMiddleware
import sqlalchemy as db
from sqlalchemy import exc, or_
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.mysql import insert

from models.tables import Base, TableTweet, TableUser, TableHashes

BAZAAR = 0
URLHAUS = 1
VIRUSSHARE = 2
VX_UNDERGROUND = 3
MALSHARE = 4
HYBRID_ANALYSIS = 5
THREATFOX = 6

MD5_REGEX = "^[a-fA-F0-9]{32}$"
SHA256_REGEX = "^[a-fA-F0-9]{64}$"

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

timeout: int = cfg.getint("requests", "timeout")

virusshare_token: str = cfg.get("virusshare", "token")
malshare_token: str = cfg.get("malshare", "token")
hybrid_analysis_token: str = cfg.get("hybrid_analysis", "token")
kaspersky_token: str = cfg.get("kaspersky", "token")

redis = redis.from_url(redis_url)

engine = db.create_engine(mysql_url, pool_pre_ping=True, pool_recycle=True)
Base.metadata.create_all(engine)

app = FastAPI(title=api_title, description=api_description, version=api_version, docs_url='/')
app.add_middleware(CORSMiddleware, allow_origins=[dashboard_url], allow_methods=["*"], allow_headers=["*"])


class Telegram(BaseModel):
    update_id: int
    message: Dict


@app.post("/telegram/webhook", include_in_schema=False)
async def telegram_webhook(request: Request):
    data = await request.body()
    print("Telegram: %s" % data)
    return {"success": True}


def get_file_hash(file_hash: str):
    file_hash = file_hash.lower()
    return {
        "bazaar": redis.getbit(file_hash, BAZAAR),
        "urlhaus": redis.getbit(file_hash, URLHAUS),
        "virusshare": redis.getbit(file_hash, VIRUSSHARE),
        "vx-underground": redis.getbit(file_hash, VX_UNDERGROUND),
        "malshare": redis.getbit(file_hash, MALSHARE),
        "hybrid-analysis": redis.getbit(file_hash, HYBRID_ANALYSIS),
        "threatfox": redis.getbit(file_hash, THREATFOX)
    }


def request_api(url: str, headers: dict = None, data: Any = None):
    logging.info("Querying -> %s" % url)
    response: dict = {}
    try:
        if data is not None:
            r = requests.post(url=url, data=data, headers=headers, timeout=timeout)
        else:
            r = requests.get(url=url, headers=headers, timeout=timeout)
        if r.status_code == 200:
            response = r.json()
        else:
            logging.warning("Request failed with status: %s (%s)" % (r.status_code, responses[r.status_code]))
        r.close()
    except requests.exceptions.RequestException as e:
        logging.warning(e)
    return response


def get_file_info(file_hash: str):
    file_hash = file_hash.lower()
    info = {"sha256": None, "md5": None, "filesize": None, "filetype": None, "ssdeep": None, "imphash": None,
            "signatures": None}

    try:
        session = sessionmaker(bind=engine, autocommit=True)()
        rows = session.query(TableHashes.sha256, TableHashes.md5, TableHashes.filesize, TableHashes.filetype,
                             TableHashes.ssdeep, TableHashes.imphash, TableHashes.signatures) \
            .filter(or_(TableHashes.sha256 == file_hash, TableHashes.md5 == file_hash))
        if rows.count() > 0:
            info = rows[0]._asdict()
            if info["signatures"] is not None:
                info["signatures"] = json.loads(info["signatures"])
            return info
    except exc.SQLAlchemyError as e:
        logging.error(e)

    if len(file_hash) == 32:
        info["md5"] = file_hash
    elif len(file_hash) == 64:
        info["sha256"] = file_hash

    is_enriched = False

    if redis.getbit(file_hash, BAZAAR) and not is_enriched:
        response = request_api(url='https://mb-api.abuse.ch/api/v1/', data={'query': 'get_info', 'hash': file_hash})
        if "data" in response and isinstance(response["data"], list):
            for entry in response["data"]:
                if isinstance(entry["md5_hash"], str):
                    info["md5"] = entry["md5_hash"].lower()
                if isinstance(entry["sha256_hash"], str):
                    info["sha256"] = entry["sha256_hash"].lower()
                if isinstance(entry["file_size"], int):
                    info["filesize"] = entry["file_size"]
                if isinstance(entry["file_type"], str):
                    info["filetype"] = entry["file_type"].upper()
                if isinstance(entry["ssdeep"], str):
                    info["ssdeep"] = entry["ssdeep"]
                if isinstance(entry["imphash"], str):
                    info["imphash"] = entry["imphash"].lower()
                if isinstance(entry["signature"], str):
                    info["signatures"] = [entry["signature"]]
                is_enriched = True

    if redis.getbit(file_hash, URLHAUS) and not is_enriched:
        data = None
        if re.match(SHA256_REGEX, file_hash):
            data = {'sha256_hash': file_hash}
        elif re.match(MD5_REGEX, file_hash):
            data = {'md5_hash': file_hash}
        if data is not None:
            response = request_api(url='https://urlhaus-api.abuse.ch/v1/payload/', data=data)
            if isinstance(response["md5_hash"], str):
                info["md5"] = response["md5_hash"].lower()
            if isinstance(response["sha256_hash"], str):
                info["sha256"] = response["sha256_hash"].lower()
            if isinstance(response["file_size"], int):
                info["filesize"] = response["file_size"]
            if isinstance(response["file_type"], str):
                info["filetype"] = response["file_type"].upper()
            if isinstance(response["ssdeep"], str):
                info["ssdeep"] = response["ssdeep"]
            if isinstance(response["imphash"], str):
                info["imphash"] = response["imphash"].lower()
            if isinstance(response["signature"], str):
                info["signatures"] = [response["signature"]]
            is_enriched = True

    if not is_enriched:
        response = request_api(url="https://opentip.kaspersky.com/api/v1/search/hash?request=%s" % file_hash,
                               headers={"X-API-KEY": kaspersky_token})
        if "FileGeneralInfo" in response:
            if "Md5" in response["FileGeneralInfo"] and isinstance(response["FileGeneralInfo"]["Md5"], str):
                info["md5"] = response["FileGeneralInfo"]["Md5"].lower()
            if "Sha256" in response["FileGeneralInfo"] and isinstance(response["FileGeneralInfo"]["Sha256"], str):
                info["sha256"] = response["FileGeneralInfo"]["Sha256"].lower()
            if "Size" in response["FileGeneralInfo"] and isinstance(response["FileGeneralInfo"]["Size"], int):
                info["filesize"] = response["FileGeneralInfo"]["Size"]
            if "Type" in response["FileGeneralInfo"] and isinstance(response["FileGeneralInfo"]["Type"], str):
                info["filetype"] = response["FileGeneralInfo"]["Type"].upper()
            detection = None
            if "DetectionsInfo" in response and isinstance(response["DetectionsInfo"], list):
                for detection_info in response["DetectionsInfo"]:
                    if detection is None or detection["LastDetectDate"] < detection_info["LastDetectDate"]:
                        detection = detection_info
                if detection is not None:
                    info["signatures"] = [detection["DetectionName"]]
                else:
                    info["signatures"] = []
            is_enriched = True

    if redis.getbit(file_hash, VIRUSSHARE) and not is_enriched:
        response = request_api(url='https://virusshare.com/apiv2/file?apikey=%s&hash=%s' %
                                   (virusshare_token, file_hash))
        try:
            if isinstance(response["md5"], str):
                info["md5"] = response["md5"].lower()
            if isinstance(response["sha256"], str):
                info["sha256"] = response["sha256"].lower()
            if isinstance(response["size"], int):
                info["filesize"] = response["size"]
            if isinstance(response["extension"], str):
                info["filetype"] = response["extension"].upper()
            if isinstance(response["ssdeep"], str):
                info["ssdeep"] = response["ssdeep"]
            if isinstance(response["imphash"], str):
                info["imphash"] = response["imphash"].lower()
            detections = set()
            if "virustotal" in response and "scans" in response["virustotal"]:
                for scanner, detection in response["virustotal"]["scans"].items():
                    if detection["result"] is not None:
                        detections.add(detection["result"])
            info["signatures"] = list(detections)
            is_enriched = True
        except ValueError as e:
            logging.error("Failed to parse response -> %s" % e)

    if redis.getbit(file_hash, HYBRID_ANALYSIS) and not is_enriched:
        response = request_api(url='https://www.hybrid-analysis.com/api/v2/search/hash', data={"hash": file_hash},
                           headers={'user-agent': 'Falcon Sandbox', 'api-key': hybrid_analysis_token})
        try:
            if isinstance(response[0]["md5"], str):
                info["md5"] = response[0]["md5"].lower()
            if isinstance(response[0]["sha256"], str):
                info["sha256"] = response[0]["sha256"].lower()
            if isinstance(response[0]["size"], int):
                info["filesize"] = response[0]["size"]
            if isinstance(response[0]["type_short"], list) and len(response[0]["type_short"]) > 0:
                info["filetype"] = response[0]["type_short"][0].upper()
            if isinstance(response[0]["ssdeep"], str):
                info["ssdeep"] = response[0]["ssdeep"]
            if isinstance(response[0]["imphash"], str):
                info["imphash"] = response[0]["imphash"].lower()
            if isinstance(response[0]["vx_family"], str):
                info["signatures"] = [response[0]["vx_family"]]
            is_enriched = True
        except ValueError as e:
            logging.error("Failed to parse response -> %s" % e)

    if redis.getbit(file_hash, MALSHARE) and not is_enriched:
        response = request_api(url='https://www.malshare.com/api.php?api_key=%s&action=details&hash=%s' %
                               (malshare_token, file_hash))
        try:
            if isinstance(response["MD5"], str):
                info["md5"] = response["MD5"].lower()
            if isinstance(response["SHA256"], str):
                info["sha256"] = response["SHA256"].lower()
            if isinstance(response["F_TYPE"], str):
                info["filetype"] = response["F_TYPE"].upper()
            if isinstance(response["SSDEEP"], str):
                info["ssdeep"] = response["SSDEEP"]
            is_enriched = True
        except ValueError as e:
            logging.error("Failed to parse response -> %s" % e)

    if is_enriched:
        mysql = engine.connect()

        mysql.execute(insert(TableHashes).values(
            sha256=info["sha256"],
            md5=info["md5"],
            filesize=info["filesize"],
            filetype=info["filetype"],
            ssdeep=info["ssdeep"],
            imphash=info["imphash"],
            signatures=json.dumps(info["signatures"])))

    return info


@app.get("/sources/md5/{md5}", description="Returns a list of sources that own this sample.", tags=["Sources"])
async def sources(md5: str = Path(None, regex=MD5_REGEX)):
    if md5 is not None:
        return get_file_hash(file_hash=md5)


@app.get("/sources/sha256/{sha256}", description="Returns a list of sources that own this sample.", tags=["Sources"])
async def sources(sha256: str = Path(None, regex=SHA256_REGEX)):
    if sha256 is not None:
        return get_file_hash(file_hash=sha256)


@app.get("/sample/md5/{md5}", description="Returns file information about a sample.", tags=["Sample"])
async def sample(md5: str = Path(None, regex=MD5_REGEX)):
    if md5 is not None:
        return get_file_info(file_hash=md5)


@app.get("/sample/sha256/{sha256}", description="Returns file information about a sample.", tags=["Sample"])
async def sample(sha256: str = Path(None, regex=SHA256_REGEX)):
    if sha256 is not None:
        return get_file_info(file_hash=sha256)


@app.get("/twitter/users", description="Returns a list of tracked Twitter users.", tags=["Twitter"])
async def twitter_users():
    results = []
    try:
        session = sessionmaker(bind=engine, autocommit=True)()
        rows = session.query(TableUser.id, TableUser.screen_name, TableUser.profile_image_url_https) \
            .filter(TableUser.protected == 0) \
            .order_by(TableUser.created_at.asc())
        for row in rows:
            result = row._asdict()
            result["id"] = str(result["id"])
            results.append(result)
    except exc.SQLAlchemyError as e:
        logging.error(e)
    return results


@app.get("/twitter/keywords", description="Returns a list of tracked Twitter keywords.", tags=["Twitter"])
async def twitter_keywords():
    return redis.smembers("twitter_keywords")


@app.get("/twitter/tweets", description="Returns a list of recent 100 Tweets with known malware hashes.",
         tags=["Twitter"])
async def twitter_tweets():
    results = []
    try:
        session = sessionmaker(bind=engine, autocommit=True)()
        rows = session.query(TableTweet.created_at, TableTweet.id, TableTweet.text, TableTweet.lang,
                             TableUser.name, TableUser.screen_name, TableUser.profile_image_url_https) \
            .filter(TableTweet.user_id == TableUser.id) \
            .order_by(TableTweet.created_at.desc()) \
            .limit(100)
        for row in rows:
            result = row._asdict()
            result["created_at"] = result["created_at"].replace(tzinfo=timezone.utc)
            result["id"] = str(result["id"])
            results.append(result)
    except exc.SQLAlchemyError as e:
        logging.error(e)
    return results
