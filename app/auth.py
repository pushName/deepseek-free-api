"""Admin 认证模块 — HTTP Basic Auth"""

import secrets
from collections.abc import Mapping
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from app.config import config_manager

security = HTTPBasic()


def extract_api_key(headers: Mapping[str, str]) -> str:
    """Read an OpenAI-style Bearer token or Anthropic-style x-api-key header."""
    x_api_key = headers.get("x-api-key", "").strip()
    if x_api_key:
        return x_api_key

    scheme, _, token = headers.get("authorization", "").partition(" ")
    if scheme.lower() == "bearer":
        return token.strip()
    return ""


def verify_api_key(provided_key: str, expected_key: str) -> bool:
    """Compare API keys without leaking partial-match timing information."""
    return bool(provided_key and expected_key) and secrets.compare_digest(
        provided_key.encode("utf-8"), expected_key.encode("utf-8")
    )


def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    """验证管理员密码。用户名固定为 admin，密码从配置读取。"""
    correct_password = config_manager.get_admin_password()
    
    # 使用 secrets.compare_digest 防时序攻击
    is_correct_username = secrets.compare_digest(
        credentials.username.encode("utf-8"),
        b"admin"
    )
    is_correct_password = secrets.compare_digest(
        credentials.password.encode("utf-8"),
        correct_password.encode("utf-8")
    )
    
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="认证失败",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials
