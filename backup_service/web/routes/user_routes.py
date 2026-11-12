"""User Management, Profile & MFA Administration Routes.

Implements Enterprise Identity & Access Management (IAM):
- User CRUD with Role-Based Access Control (Admin only)
- Self-Service Profile & Password Management
- TOTP Multi-Factor Authentication (RFC 6238) Setup, Confirmation & Teardown
- Token Revocation & Immediate Session Invalidation
"""

import json
from fastapi import APIRouter, Request, Depends, HTTPException, Form, Response, Query
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional

from backup_service.security.auth import (
    hash_password, verify_password, validate_password_strength,
    Role, require_auth, require_admin, generate_auth_token
)
from backup_service.security.totp import (
    generate_totp_secret, format_secret_for_display, generate_otpauth_uri,
    verify_totp_code, generate_recovery_codes
)

router = APIRouter(tags=["User & Profile Management"])


# ==============================================================================
# Self-Service Profile Management
# ==============================================================================

@router.get("/profile")
async def profile_page(request: Request, user: dict = Depends(require_auth)):
    """Render personal profile and security settings console."""
    templates = request.app.state.templates
    db = request.app.state.db_manager
    fresh_user = db.get_user_by_id(user["id"])
    return templates.TemplateResponse(
        request=request,
        name="profile.html",
        context={
            "user": fresh_user,
            "active_tab": "profile",
            "error": None,
            "success": None
        }
    )


@router.post("/api/v1/profile/change-password")
async def api_change_password(request: Request, body: dict, user: dict = Depends(require_auth)):
    """Change current user password, enforce complexity, and rotate token version."""
    current_password = body.get("current_password", "")
    new_password = body.get("new_password", "")
    confirm_password = body.get("confirm_password", "")

    db = request.app.state.db_manager
    fresh_user = db.get_user_by_id(user["id"])

    # 1. Verify Current Password
    if not verify_password(current_password, fresh_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")

    # 2. Match confirmation
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="New password and confirmation do not match.")

    # 3. Enforce OWASP Password Complexity
    is_valid, err_msg = validate_password_strength(new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=err_msg)

    # 4. Hash and update password (this increments token_version to invalidate other sessions)
    new_hash = hash_password(new_password)
    db.update_user_password(fresh_user["id"], new_hash)

    # 5. Issue new session token with the incremented token_version for the current connection
    refreshed_user = db.get_user_by_id(fresh_user["id"])
    new_token = generate_auth_token(
        refreshed_user["id"],
        refreshed_user["username"],
        refreshed_user["role"],
        request.app.state.master_secret,
        token_version=refreshed_user.get("token_version", 1)
    )

    request.app.state.audit_logger.log(
        action="PASSWORD_CHANGED",
        user_id=fresh_user["id"],
        username=fresh_user["username"],
        ip_address=request.client.host if request.client else "127.0.0.1",
        status="SUCCESS",
        details={"reason": "Self-service password update"}
    )

    resp = JSONResponse(content={"success": True, "message": "Password changed successfully! All other active sessions have been invalidated."})
    resp.set_cookie(
        key="backup_auth_token",
        value=new_token,
        httponly=True,
        max_age=12 * 3600,
        samesite="lax",
        secure=(request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https")
    )
    return resp


# ==============================================================================
# TOTP Multi-Factor Authentication (MFA) Setup & Teardown
# ==============================================================================

@router.post("/api/v1/profile/mfa/setup")
async def api_mfa_setup(request: Request, user: dict = Depends(require_auth)):
    """Initialize TOTP enrollment: generate secret, QR URI, and emergency recovery codes."""
    db = request.app.state.db_manager
    vault = request.app.state.vault
    fresh_user = db.get_user_by_id(user["id"])

    # Generate 160-bit RFC 6238 Base32 Secret
    secret_b32 = generate_totp_secret()
    formatted_secret = format_secret_for_display(secret_b32)
    otpauth_uri = generate_otpauth_uri(secret_b32, fresh_user["username"], issuer="TechLIMS")

    # Generate 8 Emergency Recovery Codes
    plain_codes, hashed_codes = generate_recovery_codes(num_codes=8)

    # Encrypt secret with AES-256-GCM Vault
    encrypted_secret = vault.encrypt(secret_b32)

    # Temporarily persist encrypted secret & recovery codes with mfa_enabled=0 until confirmed
    db.set_user_mfa(
        fresh_user["id"],
        mfa_enabled=0,
        totp_secret_encrypted=encrypted_secret,
        recovery_codes_json=json.dumps(hashed_codes)
    )

    return {
        "success": True,
        "secret": secret_b32,
        "formatted_secret": formatted_secret,
        "otpauth_uri": otpauth_uri,
        "recovery_codes": plain_codes
    }


@router.post("/api/v1/profile/mfa/confirm")
async def api_mfa_confirm(request: Request, body: dict, user: dict = Depends(require_auth)):
    """Confirm TOTP setup by verifying the first 6-digit code from authenticator app."""
    code = body.get("code", "").strip()
    db = request.app.state.db_manager
    vault = request.app.state.vault
    fresh_user = db.get_user_by_id(user["id"])

    if not fresh_user.get("totp_secret_encrypted"):
        raise HTTPException(status_code=400, detail="MFA setup has not been initiated. Please click Setup first.")

    # Decrypt TOTP Secret
    try:
        secret_b32 = vault.decrypt(fresh_user["totp_secret_encrypted"])
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to decrypt MFA secret key.")

    # Verify submitted code
    is_valid, step = verify_totp_code(secret_b32, code, last_step_used=0)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid 6-digit verification code. Make sure your device clock is synchronized.")

    # Activate MFA permanently
    db.set_user_mfa(
        fresh_user["id"],
        mfa_enabled=1,
        totp_secret_encrypted=fresh_user["totp_secret_encrypted"],
        recovery_codes_json=fresh_user["recovery_codes_json"]
    )
    db.update_last_totp_step(fresh_user["id"], step)

    request.app.state.audit_logger.log(
        action="MFA_ENABLED",
        user_id=fresh_user["id"],
        username=fresh_user["username"],
        ip_address=request.client.host if request.client else "127.0.0.1",
        status="SUCCESS",
        details={"method": "TOTP RFC 6238"}
    )

    return {"success": True, "message": "Two-Factor Authentication (TOTP) successfully activated on your account!"}


@router.post("/api/v1/profile/mfa/disable")
async def api_mfa_disable(request: Request, body: dict, user: dict = Depends(require_auth)):
    """Disable TOTP MFA with mandatory password re-authentication safeguard."""
    password = body.get("password", "")
    db = request.app.state.db_manager
    fresh_user = db.get_user_by_id(user["id"])

    # Password re-authentication safeguard
    if not verify_password(password, fresh_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect account password. Cannot disable Two-Factor Authentication.")

    db.disable_user_mfa(fresh_user["id"])

    request.app.state.audit_logger.log(
        action="MFA_DISABLED",
        user_id=fresh_user["id"],
        username=fresh_user["username"],
        ip_address=request.client.host if request.client else "127.0.0.1",
        status="SUCCESS"
    )

    return {"success": True, "message": "Two-Factor Authentication has been disabled on your account."}


# ==============================================================================
# Administrator User Management (RBAC: Admin Only)
# ==============================================================================

@router.get("/users")
async def users_page(request: Request, user: dict = Depends(require_admin)):
    """Render User Management Console (Admins only)."""
    templates = request.app.state.templates
    db = request.app.state.db_manager
    users = db.list_users()

    return templates.TemplateResponse(
        request=request,
        name="users.html",
        context={
            "user": user,
            "users": users,
            "active_tab": "users",
            "roles": [Role.ADMIN, Role.OPERATOR, Role.AUDITOR],
            "error": None
        }
    )


@router.post("/api/v1/users")
async def api_create_user(request: Request, body: dict, admin: dict = Depends(require_admin)):
    """Create a new platform user with specified role and password."""
    username = body.get("username", "").strip().lower()
    email = body.get("email", "").strip()
    role = body.get("role", Role.OPERATOR)
    password = body.get("password", "")

    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")

    if role not in Role.ALL_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {', '.join(Role.ALL_ROLES)}")

    # Enforce Password Complexity
    is_valid, err_msg = validate_password_strength(password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=err_msg)

    db = request.app.state.db_manager
    existing = db.get_user_by_username(username)
    if existing:
        raise HTTPException(status_code=400, detail=f"Username '{username}' is already taken.")

    pwd_hash = hash_password(password)
    new_user_id = db.create_user(username, email, pwd_hash, role)

    request.app.state.audit_logger.log(
        action="USER_CREATED",
        user_id=admin["id"],
        username=admin["username"],
        resource_type="user",
        resource_id=str(new_user_id),
        ip_address=request.client.host if request.client else "127.0.0.1",
        status="SUCCESS",
        details={"created_username": username, "assigned_role": role}
    )

    return {"success": True, "user_id": new_user_id, "message": f"User '{username}' created successfully."}


@router.put("/api/v1/users/{user_id}")
async def api_update_user(user_id: int, body: dict, request: Request, admin: dict = Depends(require_admin)):
    """Update user email, role, and active status."""
    email = body.get("email")
    role = body.get("role", Role.OPERATOR)
    is_active = 1 if body.get("is_active", True) else 0

    if role not in Role.ALL_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role specified.")

    db = request.app.state.db_manager
    target = db.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")

    # Guard: prevent removing admin role from the last active admin
    if target["role"] == Role.ADMIN and role != Role.ADMIN:
        with db.connection() as conn:
            cnt = conn.execute("SELECT COUNT(*) as c FROM users WHERE role = ? AND is_active = 1", (Role.ADMIN,)).fetchone()["c"]
            if cnt <= 1:
                raise HTTPException(status_code=400, detail="Cannot demote the sole remaining active administrator.")

    db.update_user(user_id, email, role, is_active)

    request.app.state.audit_logger.log(
        action="USER_UPDATED",
        user_id=admin["id"],
        username=admin["username"],
        resource_type="user",
        resource_id=str(user_id),
        ip_address=request.client.host if request.client else "127.0.0.1",
        status="SUCCESS",
        details={"updated_username": target["username"], "new_role": role, "is_active": is_active}
    )

    return {"success": True, "message": f"User '{target['username']}' updated successfully."}


@router.post("/api/v1/users/{user_id}/reset-password")
async def api_reset_user_password(user_id: int, body: dict, request: Request, admin: dict = Depends(require_admin)):
    """Administrative password reset (immediately revokes target user's active tokens)."""
    new_password = body.get("new_password", "")
    is_valid, err_msg = validate_password_strength(new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=err_msg)

    db = request.app.state.db_manager
    target = db.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")

    new_hash = hash_password(new_password)
    db.update_user_password(user_id, new_hash)

    request.app.state.audit_logger.log(
        action="PASSWORD_RESET_ADMIN",
        user_id=admin["id"],
        username=admin["username"],
        resource_type="user",
        resource_id=str(user_id),
        ip_address=request.client.host if request.client else "127.0.0.1",
        status="SUCCESS",
        details={"target_username": target["username"]}
    )

    return {"success": True, "message": f"Password reset for '{target['username']}'. Active sessions have been invalidated."}


@router.delete("/api/v1/users/{user_id}")
async def api_delete_user(user_id: int, request: Request, admin: dict = Depends(require_admin)):
    """Safely delete platform user enforcing self-deletion and last-admin safeguards."""
    db = request.app.state.db_manager
    success, msg = db.delete_user(user_id, requesting_user_id=admin["id"])
    if not success:
        raise HTTPException(status_code=400, detail=msg)

    request.app.state.audit_logger.log(
        action="USER_DELETED",
        user_id=admin["id"],
        username=admin["username"],
        resource_type="user",
        resource_id=str(user_id),
        ip_address=request.client.host if request.client else "127.0.0.1",
        status="SUCCESS"
    )

    return {"success": True, "message": msg}
