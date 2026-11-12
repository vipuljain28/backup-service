"""Authentication and User Management Routes.

Adheres strictly to OWASP & Pentest Security Guidelines:
- CWE-307: Sliding-window rate limiter preventing automated brute-force attacks
- CWE-208: Constant-time authentication with dummy hash mitigation against user enumeration
- CWE-614: Dynamic TLS / Reverse-proxy aware secure cookie flag
"""

from fastapi import APIRouter, Request, Depends, HTTPException, Form, Response
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional

from backup_service.security.auth import (
    hash_password, verify_password, generate_auth_token, verify_auth_token, Role
)
from backup_service.security.rate_limiter import auth_rate_limiter

router = APIRouter(tags=["Authentication"])

# Pre-computed dummy hash to guarantee identical PBKDF2 execution time (~50ms)
# when testing non-existent usernames, completely eliminating timing attacks (CWE-208).
DUMMY_PASSWORD_HASH = hash_password("constant_dummy_timing_hash_for_mitigation_9988!")


def is_request_secure(request: Request) -> bool:
    """Determine if connection is TLS encrypted directly or via trusted reverse proxy."""
    if request.url.scheme == "https":
        return True
    proto = request.headers.get("x-forwarded-proto", "").lower()
    if proto == "https":
        return True
    ssl_header = request.headers.get("x-forwarded-ssl", "").lower()
    if ssl_header == "on":
        return True
    return False


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


def require_operator_or_admin(request: Request, user: dict = Depends(require_auth)) -> dict:
    if user.get("role") not in (Role.ADMIN, Role.OPERATOR):
        raise HTTPException(status_code=403, detail="Operator or Administrator privilege required")
    return user


@router.get("/login")
async def login_page(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/", status_code=303)
    templates = request.app.state.templates
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None})


@router.post("/login")
async def login_post(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    templates = request.app.state.templates
    ip = request.client.host if request.client else "127.0.0.1"
    clean_username = username.strip().lower()

    # 1. Anti-Brute-Force Rate Limiting Verification (CWE-307)
    ip_key = f"ip:{ip}"
    user_key = f"user:{clean_username}"
    is_locked_ip, retry_ip = auth_rate_limiter.is_locked(ip_key)
    is_locked_user, retry_user = auth_rate_limiter.is_locked(user_key)

    if is_locked_ip or is_locked_user:
        lockout_duration = max(retry_ip, retry_user)
        request.app.state.audit_logger.log(
            action="LOGIN_LOCKED",
            username=clean_username,
            ip_address=ip,
            status="BLOCKED",
            details={"reason": "Excessive failed login attempts", "retry_after": lockout_duration}
        )
        minutes = max(1, (lockout_duration + 59) // 60)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": f"Too many failed login attempts. Access is locked for {minutes} minute(s). Please try again later."},
            status_code=429,
            headers={"Retry-After": str(lockout_duration)}
        )

    # 2. Constant-Time Authentication to Prevent Timing Attacks (CWE-208)
    db = request.app.state.db_manager
    user = db.get_user_by_username(clean_username)

    target_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
    password_is_valid = verify_password(password, target_hash)

    if not user or not password_is_valid:
        # Record failure for both IP and target username
        ip_now_locked, ip_wait = auth_rate_limiter.record_failure(ip_key)
        user_now_locked, user_wait = auth_rate_limiter.record_failure(user_key)

        request.app.state.audit_logger.log(
            action="LOGIN_FAILED",
            username=clean_username,
            ip_address=ip,
            status="FAILED",
            details={
                "reason": "Invalid credentials",
                "ip_locked": ip_now_locked,
                "user_locked": user_now_locked
            }
        )

        if ip_now_locked or user_now_locked:
            lockout_duration = max(ip_wait, user_wait)
            minutes = max(1, (lockout_duration + 59) // 60)
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": f"Account locked due to 5 consecutive failed attempts. Please retry after {minutes} minute(s)."},
                status_code=429,
                headers={"Retry-After": str(lockout_duration)}
            )

        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid username or password"},
            status_code=401
        )

    # Successful Authentication: Reset rate limiter tracking
    auth_rate_limiter.reset(ip_key)
    auth_rate_limiter.reset(user_key)

    token = generate_auth_token(
        user["id"], user["username"], user["role"], request.app.state.master_secret
    )

    request.app.state.audit_logger.log(
        action="LOGIN_SUCCESS",
        user_id=user["id"],
        username=user["username"],
        ip_address=ip,
        status="SUCCESS"
    )

    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        key="backup_auth_token",
        value=token,
        httponly=True,
        max_age=12 * 3600,
        samesite="lax",
        secure=is_request_secure(request)
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
    ip = request.client.host if request.client else "127.0.0.1"
    username = body.get("username", "").strip().lower()
    password = body.get("password", "")

    # Rate Limiting Check
    ip_key = f"ip:{ip}"
    user_key = f"user:{username}"
    is_locked_ip, retry_ip = auth_rate_limiter.is_locked(ip_key)
    is_locked_user, retry_user = auth_rate_limiter.is_locked(user_key)

    if is_locked_ip or is_locked_user:
        lockout = max(retry_ip, retry_user)
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts. Retry after {lockout} seconds.",
            headers={"Retry-After": str(lockout)}
        )

    db = request.app.state.db_manager
    user = db.get_user_by_username(username)
    target_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
    password_is_valid = verify_password(password, target_hash)

    if not user or not password_is_valid:
        ip_now_locked, ip_wait = auth_rate_limiter.record_failure(ip_key)
        user_now_locked, user_wait = auth_rate_limiter.record_failure(user_key)

        request.app.state.audit_logger.log(
            action="API_LOGIN_FAILED",
            username=username,
            ip_address=ip,
            status="FAILED"
        )

        if ip_now_locked or user_now_locked:
            lockout = max(ip_wait, user_wait)
            raise HTTPException(
                status_code=429,
                detail=f"Account locked due to excessive failed attempts. Retry after {lockout} seconds.",
                headers={"Retry-After": str(lockout)}
            )

        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Reset Rate Limiter
    auth_rate_limiter.reset(ip_key)
    auth_rate_limiter.reset(user_key)

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
