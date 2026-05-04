from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import PlainTextResponse

from app.core.inventory_store import inventory_store
from app.models.inventory import C2Row, HostRow, UserRow

router = APIRouter(prefix="/api/inventory", tags=["inventory"])


@router.get("/hosts")
def list_hosts():
    inventory_store.bootstrap_if_empty()
    return [h.model_dump() for h in inventory_store.list_hosts()]


@router.post("/hosts")
def create_host(row: HostRow):
    inventory_store.bootstrap_if_empty()
    return inventory_store.upsert_host(row).model_dump()


@router.put("/hosts/{hid}")
def update_host(hid: str, row: HostRow):
    inventory_store.bootstrap_if_empty()
    row.id = hid
    return inventory_store.upsert_host(row).model_dump()


@router.delete("/hosts/{hid}")
def delete_host(hid: str):
    if not inventory_store.delete_host(hid):
        raise HTTPException(404)
    return {"ok": True}


@router.get("/users")
def list_users():
    inventory_store.bootstrap_if_empty()
    return [u.model_dump() for u in inventory_store.list_users()]


@router.post("/users")
def create_user(row: UserRow):
    inventory_store.bootstrap_if_empty()
    return inventory_store.upsert_user(row).model_dump()


@router.put("/users/{uid}")
def update_user(uid: str, row: UserRow):
    inventory_store.bootstrap_if_empty()
    row.id = uid
    return inventory_store.upsert_user(row).model_dump()


@router.delete("/users/{uid}")
def delete_user(uid: str):
    if not inventory_store.delete_user(uid):
        raise HTTPException(404)
    return {"ok": True}


@router.get("/c2")
def list_c2():
    inventory_store.bootstrap_if_empty()
    return [c.model_dump() for c in inventory_store.list_c2()]


@router.post("/c2")
def create_c2(row: C2Row):
    inventory_store.bootstrap_if_empty()
    return inventory_store.upsert_c2(row).model_dump()


@router.put("/c2/{cid}")
def update_c2(cid: str, row: C2Row):
    inventory_store.bootstrap_if_empty()
    row.id = cid
    return inventory_store.upsert_c2(row).model_dump()


@router.delete("/c2/{cid}")
def delete_c2(cid: str):
    if not inventory_store.delete_c2(cid):
        raise HTTPException(404)
    return {"ok": True}


@router.post("/hosts/import")
async def import_hosts(file: UploadFile = File(...)):
    content = await file.read()
    inventory_store.import_hosts_replace(content)
    return {"ok": True}


@router.get("/hosts/export")
def export_hosts():
    data = inventory_store.export_hosts_bytes()
    return PlainTextResponse(content=data.decode("utf-8-sig", errors="replace"), media_type="text/csv")
