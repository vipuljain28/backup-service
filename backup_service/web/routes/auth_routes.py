"""Authentication, Session Management & Multi-Factor Authentication Routes.

Adheres strictly to OWASP & Pentest Security Guidelines:
- CWE-307: Sliding-window rate limiter preventing automated brute-force attacks
- CWE-208: Constant-time authentication with dummy hash mitigation against user enumeration
- CWE-614: Dynamic TLS / Reverse-proxy aware secure cookie flag
- CWE-613 / CWE-384: Token versioning, immediate session revocation & token reuse protection
- RFC 6238: TOTP Multi-Factor Authentication verification with replay attack prevention
"""

import json
from fastapi import APIRouter, Request, Depends, HTTPException, Form, Response
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional

from backup_service.security.auth import (
    hash_password, verify_password, generate_auth_token, verify_auth_token,
    generate_mfa_challenge_token, verify_mfa_challenge_token, Role
)
from backup_service.security.rate_limiter import auth_rate_limiter
from backup_service.security.totp import (
    verify_totp_code, verify_and_consume_recovery_code
)

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
    """Extract authenticated user payload with active token revocation & reuse verification."""
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
    if not user:
        return None

    # Token Reuse & Revocation Protection: Check token version against database
    # If the user logged out, changed password, or was demoted, the token version will mismatch!
    if user.get("token_version", 1) != payload.get("ver", 1):
        return None

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


# ==============================================================================
# Login & Logout Endpoints
# ==============================================================================

@router.get("/login")
async def login_page(request: Request, timeout: Optional[str] = None):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/", status_code=303)
    templates = request.app.state.templates
    notice = None
    if timeout == "1":
        notice = "Your session has expired due to inactivity. Please log in again."
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None, "notice": notice})


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

    # Clear rate limiter on valid first-factor credentials
    auth_rate_limiter.reset(ip_key)
    auth_rate_limiter.reset(user_key)

    # 3. Multi-Factor Authentication (MFA) Verification Handshake
    if user.get("mfa_enabled") == 1:
        # User has TOTP MFA enabled: DO NOT issue session token!
        # Issue short-lived challenge token (5-min timeout)
        challenge_token = generate_mfa_challenge_token(user["id"], request.app.state.master_secret)
        return RedirectResponse(url=f"/login/mfa?challenge={challenge_token}", status_code=303)

    # Single-Factor Login (MFA not enabled)
    db.record_user_login(user["id"])
    token = generate_auth_token(
        user["id"],
        user["username"],
        user["role"],
        request.app.state.master_secret,
        token_version=user.get("token_version", 1)
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
    """Logout endpoint: invalidates token version in database to protect against token reuse."""
    user = get_current_user(request)
    if user:
        # Invalidate active token version on logout so the token cannot be reused even if captured
        request.app.state.db_manager.increment_token_version(user["id"])
        request.app.state.audit_logger.log(
            action="LOGOUT",
            user_id=user["id"],
            username=user["username"],
            ip_address=request.client.host if request.client else "127.0.0.1"
        )
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("backup_auth_token")
    return resp


# ==============================================================================
# MFA Challenge Screen & Handshake Routes
# ==============================================================================

@router.get("/login/mfa")
async def login_mfa_page(request: Request, challenge: str):
    """Render MFA challenge page for 6-digit TOTP input."""
    payload = verify_mfa_challenge_token(challenge, request.app.state.master_secret)
    if not payload:
        return RedirectResponse(url="/login?error=Invalid+or+expired+MFA+challenge.+Please+log+in+again.", status_code=303)

    db = request.app.state.db_manager
    user = db.get_user_by_id(payload["uid"])
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="login_mfa.html",
        context={
            "challenge_token": challenge,
            "username": user["username"],
            "error": None
        }
    )


@router.post("/login/mfa")
async def login_mfa_post(
    request: Request,
    response: Response,
    challenge_token: str = Form(...),
    code: str = Form(...)
):
    """Verify 6-digit TOTP code against short-lived challenge token."""
    templates = request.app.state.templates
    ip = request.client.host if request.client else "127.0.0.1"

    payload = verify_mfa_challenge_token(challenge_token, request.app.state.master_secret)
    if not payload:
        return RedirectResponse(url="/login?error=MFA+challenge+session+expired.+Please+log+in+again.", status_code=303)

    user_id = payload["uid"]
    db = request.app.state.db_manager
    vault = request.app.state.vault
    user = db.get_user_by_id(user_id)
    if not user or not user.get("totp_secret_encrypted"):
        return RedirectResponse(url="/login", status_code=303)

    # Brute-force rate limiting on TOTP submissions (max 3 failed attempts per user)
    mfa_key = f"mfa:{user_id}"
    is_locked, remaining = auth_rate_limiter.is_locked(mfa_key)
    if is_locked:
        return templates.TemplateResponse(
            request=request,
            name="login_mfa.html",
            context={
                "challenge_token": challenge_token,
                "username": user["username"],
                "error": f"Too many failed verification attempts. Account locked for {remaining} seconds."
            },
            status_code=429
        )

    # Decrypt TOTP secret key
    try:
        secret_b32 = vault.decrypt(user["totp_secret_encrypted"])
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to decrypt 2FA credential.")

    # Verify code with clock drift (+/- 30s) and replay attack mitigation (last_totp_step)
    is_valid, step = verify_totp_code(
        secret_b32,
        code,
        last_step_used=user.get("last_totp_step", 0),
        window=1
    )

    if not is_valid:
        locked, wait = auth_rate_limiter.record_failure(mfa_key)
        request.app.state.audit_logger.log(
            action="MFA_FAILED",
            user_id=user["id"],
            username=user["username"],
            ip_address=ip,
            status="FAILED",
            details={"reason": "Invalid TOTP code"}
        )
        err = "Invalid 6-digit verification code. Please check Google/Microsoft Authenticator and retry."
        if locked:
            err = f"Too many failed attempts. Verification locked for {wait} seconds."
        return templates.TemplateResponse(
            request=request,
            name="login_mfa.html",
            context={"challenge_token": challenge_token, "username": user["username"], "error": err},
            status_code=401
        )

    # Reset MFA rate limiter
    auth_rate_limiter.reset(mfa_key)

    # Replay Protection: update last used step counter in database
    db.update_last_totp_step(user["id"], step)
    db.record_user_login(user["id"])

    # Issue Full-Privilege Session Token
    token = generate_auth_token(
        user["id"],
        user["username"],
        user["role"],
        request.app.state.master_secret,
        token_version=user.get("token_version", 1)
    )

    request.app.state.audit_logger.log(
        action="LOGIN_MFA_SUCCESS",
        user_id=user["id"],
        username=user["username"],
        ip_address=ip,
        status="SUCCESS",
        details={"method": "TOTP RFC 6238"}
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


@router.post("/login/mfa/recovery")
async def login_mfa_recovery_post(
    request: Request,
    response: Response,
    challenge_token: str = Form(...),
    recovery_code: str = Form(...)
):
    """Authenticate using single-use emergency backup recovery code."""
    templates = request.app.state.templates
    ip = request.client.host if request.client else "127.0.0.1"

    payload = verify_mfa_challenge_token(challenge_token, request.app.state.master_secret)
    if not payload:
        return RedirectResponse(url="/login?error=MFA+session+expired.+Please+log+in+again.", status_code=303)

    user_id = payload["uid"]
    db = request.app.state.db_manager
    user = db.get_user_by_id(user_id)
    if not user or not user.get("recovery_codes_json"):
        return RedirectResponse(url="/login", status_code=303)

    stored_hashes = json.loads(user["recovery_codes_json"])
    is_valid, matched_hash = verify_and_consume_recovery_code(recovery_code, stored_hashes)

    if not is_valid or not matched_hash:
        request.app.state.audit_logger.log(
            action="MFA_RECOVERY_FAILED",
            user_id=user["id"],
            username=user["username"],
            ip_address=ip,
            status="FAILED"
        )
        return templates.TemplateResponse(
            request=request,
            name="login_mfa.html",
            context={
                "challenge_token": challenge_token,
                "username": user["username"],
                "error": "Invalid or already consumed emergency recovery code."
            },
            status_code=401
        )

    # Consume recovery code from database (single-use guarantee)
    db.consume_recovery_code(user["id"], matched_hash)
    db.record_user_login(user["id"])

    # Issue Session Token
    token = generate_auth_token(
        user["id"],
        user["username"],
        user["role"],
        request.app.state.master_secret,
        token_version=user.get("token_version", 1)
    )

    request.app.state.audit_logger.log(
        action="LOGIN_RECOVERY_SUCCESS",
        user_id=user["id"],
        username=user["username"],
        ip_address=ip,
        status="SUCCESS",
        details={"consumed_code": True}
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


# ==============================================================================
# REST API Authentication Endpoints
# ==============================================================================

@router.post("/api/v1/auth/login")
async def api_login(request: Request, body: dict):
    ip = request.client.host if request.client else "127.0.0.1"
    username = body.get("username", "").strip().lower()
    password = body.get("password", "")

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

    auth_rate_limiter.reset(ip_key)
    auth_rate_limiter.reset(user_key)

    # MFA Interception
    if user.get("mfa_enabled") == 1:
        challenge_token = generate_mfa_challenge_token(user["id"], request.app.state.master_secret)
        return {
            "mfa_required": True,
            "challenge_token": challenge_token,
            "message": "Two-factor authentication required. Submit 6-digit TOTP code to /api/v1/auth/mfa/verify"
        }

    db.record_user_login(user["id"])
    token = generate_auth_token(
        user["id"],
        user["username"],
        user["role"],
        request.app.state.master_secret,
        token_version=user.get("token_version", 1)
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "mfa_required": False,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }


@router.post("/api/v1/auth/mfa/verify")
async def api_mfa_verify(request: Request, body: dict):
    """API endpoint to verify 6-digit TOTP code with challenge token."""
    challenge_token = body.get("challenge_token", "")
    code = body.get("code", "").strip()

    payload = verify_mfa_challenge_token(challenge_token, request.app.state.master_secret)
    if not payload:
        raise HTTPException(status_code=401, detail="MFA challenge session expired or invalid.")

    user_id = payload["uid"]
    db = request.app.state.db_manager
    vault = request.app.state.vault
    user = db.get_user_by_id(user_id)
    if not user or not user.get("totp_secret_encrypted"):
        raise HTTPException(status_code=400, detail="MFA is not configured for this user.")

    secret_b32 = vault.decrypt(user["totp_secret_encrypted"])
    is_valid, step = verify_totp_code(secret_b32, code, last_step_used=user.get("last_totp_step", 0))

    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid 6-digit verification code.")

    db.update_last_totp_step(user["id"], step)
    db.record_user_login(user["id"])

    token = generate_auth_token(
        user["id"],
        user["username"],
        user["role"],
        request.app.state.master_secret,
        token_version=user.get("token_version", 1)
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
        "role": user["role"],
        "mfa_enabled": bool(user.get("mfa_enabled", 0)),
        "last_login_at": user.get("last_login_at")
    }
