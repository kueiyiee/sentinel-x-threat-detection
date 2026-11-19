import os
import secrets
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

basic = HTTPBasic(auto_error=False)

def require_admin(credentials: HTTPBasicCredentials | None = Depends(basic)) -> str:
    expected_user = os.getenv("SENTINEL_ADMIN_USERNAME", "")
    expected_password = os.getenv("SENTINEL_ADMIN_PASSWORD", "")
    if not expected_user or not expected_password:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Administrator credentials are not configured. Set SENTINEL_ADMIN_USERNAME and SENTINEL_ADMIN_PASSWORD.",
        )
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Administrator sign-in required.",
            headers={"WWW-Authenticate": "Basic"},
        )
    valid_user = secrets.compare_digest(credentials.username, expected_user)
    valid_password = secrets.compare_digest(credentials.password, expected_password)
    if not (valid_user and valid_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid administrator credentials.",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username
