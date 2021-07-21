from fastapi import APIRouter

router = APIRouter(prefix="/api")


@router.get("/")
async def read_items():
    return {"hello": "bye"}
