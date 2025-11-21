"""GitHub OAuth and API integration."""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


async def exchange_code_for_token(code: str, client_id: str, client_secret: str, redirect_uri: str) -> str:
    """Exchange GitHub OAuth code for access token."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Accept": "application/json"},
            timeout=10.0,
        )
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise ValueError(f"GitHub OAuth error: {data.get('error_description', data['error'])}")
        return data["access_token"]


async def fetch_user_info(access_token: str) -> dict[str, Any]:
    """Fetch authenticated user information from GitHub."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()


async def fetch_user_repositories(access_token: str, limit: int = 10) -> list[dict[str, Any]]:
    """Fetch user's repositories from GitHub."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.github.com/user/repos",
            headers={
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github.v3+json",
            },
            params={"sort": "updated", "per_page": limit},
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()


async def fetch_repository_contents(access_token: str, owner: str, repo: str, path: str = "") -> list[dict[str, Any]]:
    """Fetch repository contents (files/directories)."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            headers={
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()
