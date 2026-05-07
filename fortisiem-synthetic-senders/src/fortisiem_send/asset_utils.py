from __future__ import annotations

import random

from .models import Asset, UserAD, VMwareUser


def pick_asset(assets: list[Asset], source_type: str, fallback: Asset) -> Asset:
    selected = [a for a in assets if a.source_type == source_type]
    return random.choice(selected) if selected else fallback


def find_asset_by_ip(assets: list[Asset], ip: str) -> Asset | None:
    for asset in assets:
        if asset.ip == ip:
            return asset
    return None


def find_user_by_sam(users: list[UserAD], sam: str) -> UserAD | None:
    sam_lower = sam.lower()
    for user in users:
        if user.samaccountname.lower() == sam_lower:
            return user
    return None


def find_vmware_user(vmware_users: list[VMwareUser], value: str) -> VMwareUser | None:
    v = value.lower()
    for user in vmware_users:
        full = f"{user.username}@{user.realm}".lower()
        if user.username.lower() == v or full == v:
            return user
    return None
