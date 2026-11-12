"""Authentication and User Management Routes."""

from fastapi import APIRouter, Request, Depends, HTTPException, Form, Response
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional

from backup_service.security.auth import (
    hash_password, verify_password, generate_auth_token, verify_auth_token, Role
)

router = APIRouter(tags=["Authentication"])


def get_current_user(request: Request) -> Optional[dict]:
    """Extract authenticated user payload from Bearer header or HTTP-only cookie."""
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "backup_auth_token" in request.cookies:
        token = request.cookies["backup_auth_token"]

    if not token:
        return None

    db_manager = request.app.state.db_manager
    master_secret = request.app.state.master_secret
    payload = verify_auth_token(token, master_secret)
    if not payload:
        return None

    user = db_manager.get_user_by_id(payload["uid"])
    return user


def require_auth(request: Request) -> dict:
    user = get_current_user(request)
    if not user:
        if "text/html" in request.headers.get("Accept", ""):
            raise HTTPException(status_code=307, headers={"Location": "/login"})
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_admin(request: Request, user: dict = Depends(require_auth)) -> dict:
    if user.get("role") != Role.ADMIN:
        raise HTTPException(status_code=403, detail="Administrator privilege required")
    return user


@router.get("/login")
async def login_page(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/", status_code=303)
    templates = request.app.state.templates
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
async def login_post(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    db = request.app.state.db_manager
    user = db.get_user_by_username(username.strip())

    if not user or not verify_password(password, user["password_hash"]):
        request.app.state.audit_logger.log(
            action="LOGIN_FAILED",
            username=username,
            ip_address=request.client.host if request.client else "127.0.0.1",
            status="FAILED",
            details={"reason": "Invalid credentials"}
        )
        templates = request.app.state.templates
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid username or password"})

    token = generate_auth_token(
        user["id"], user["username"], user["role"], request.app.state.master_secret
    )

    request.app.state.audit_logger.log(
        action="LOGIN_SUCCESS",
        user_id=user["id"],
        username=user["username"],
        ip_address=request.client.host if request.client else "127.0.0.1",
        status="SUCCESS"
    )

    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        key="backup_auth_token",
        value=token,
        httponly=True,
        max_age=12 * 3600,
        samesite="lax",
        secure=False  # Set True in production TLS
    )
    return resp


@router.get("/logout")
async def logout(request: Request):
    user = get_current_user(request)
    if user:
        request.app.state.audit_logger.log(
            action="LOGOUT",
            user_id=user["id"],
            username=user["username"],
            ip_address=request.client.host if request.client else "127.0.0.1"
        )
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("backup_auth_token")
    return resp


@router.post("/api/v1/auth/login")
async def api_login(request: Request, body: dict):
    username = body.get("username", "").strip()
    password = body.get("password", "")
    db = request.app.state.db_manager

    user = db.get_user_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = generate_auth_token(
        user["id"], user["username"], user["role"], request.app.state.master_secret
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }


@router.get("/api/v1/auth/me")
async def api_me(user: dict = Depends(require_auth)):
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"]
    }
