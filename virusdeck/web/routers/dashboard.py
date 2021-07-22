from fastapi import APIRouter

router = APIRouter(prefix="/dashboard")


@router.get("/")
async def read_items():
    return {"hello": "bye"}
