"""LDAP / Active Directory integration for the Canadian Municipal AI Gateway.

When enabled (LDAP_ENABLED=true), staff can authenticate with their
Active Directory credentials instead of manually created API keys.

On successful LDAP authentication, the gateway auto-provisions a gateway
API key for the user. Subsequent requests use the provisioned key.

Authentication endpoint:
  POST /auth/ldap  →  {"username": "jsmith", "password": "..."}
  Returns: {"key": "...", "department": "...", "description": "..."}

Supports:
  - Simple bind authentication
  - STARTTLS for encrypted connections
  - Configurable user filter and department attribute mapping

Configuration via environment variables:
  LDAP_ENABLED        - true/false (default: false)
  LDAP_SERVER         - LDAP server hostname
  LDAP_PORT           - LDAP port (default: 389, or 636 for LDAPS)
  LDAP_USE_SSL        - Use LDAPS (default: false)
  LDAP_STARTTLS       - Use STARTTLS on non-SSL connection (default: true)
  LDAP_BASE_DN        - Base DN for user searches
  LDAP_BIND_DN        - Service account DN for searching
  LDAP_BIND_PASSWORD  - Service account password
  LDAP_USER_FILTER    - User search filter (default: (sAMAccountName={username}))
  LDAP_DEPT_ATTRIBUTE - Attribute for department (default: department)
"""

from __future__ import annotations

import os

from logging_config import get_logger

logger = get_logger("ldap_auth")

# ── Configuration ────────────────────────────────────────────────────────────

LDAP_ENABLED = os.getenv("LDAP_ENABLED", "false").lower() == "true"
LDAP_SERVER = os.getenv("LDAP_SERVER", "")
LDAP_PORT = int(os.getenv("LDAP_PORT", "389"))
LDAP_USE_SSL = os.getenv("LDAP_USE_SSL", "false").lower() == "true"
LDAP_STARTTLS = os.getenv("LDAP_STARTTLS", "true").lower() == "true"
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN", "")
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD", "")
LDAP_USER_FILTER = os.getenv("LDAP_USER_FILTER", "(sAMAccountName={username})")
LDAP_DEPT_ATTRIBUTE = os.getenv("LDAP_DEPT_ATTRIBUTE", "department")


def is_ldap_enabled() -> bool:
    """Return True if LDAP integration is configured and enabled."""
    return LDAP_ENABLED and bool(LDAP_SERVER) and bool(LDAP_BASE_DN)


def ldap_authenticate(username: str, password: str) -> dict | None:
    """Authenticate a user against LDAP/AD.

    Returns a dict with user info on success, or None on failure.
    Result: {"dn": "...", "username": "...", "department": "...", "display_name": "..."}
    """
    if not is_ldap_enabled():
        return None

    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, SUBTREE, Tls
        import ssl
    except ImportError:
        logger.error("ldap3_not_installed", hint="pip install ldap3")
        return None

    try:
        # Build server configuration
        tls_config = None
        if LDAP_USE_SSL or LDAP_STARTTLS:
            tls_config = Tls(validate=ssl.CERT_NONE)

        server = Server(
            LDAP_SERVER,
            port=LDAP_PORT,
            use_ssl=LDAP_USE_SSL,
            tls=tls_config,
            get_info=ALL,
        )

        # Step 1: Bind with service account to search for the user
        conn = Connection(
            server,
            user=LDAP_BIND_DN,
            password=LDAP_BIND_PASSWORD,
            auto_bind=False,
        )
        conn.open()

        if LDAP_STARTTLS and not LDAP_USE_SSL:
            conn.start_tls()

        if not conn.bind():
            logger.warning("ldap_service_bind_failed", server=LDAP_SERVER)
            conn.unbind()
            return None

        # Step 2: Search for the user
        search_filter = LDAP_USER_FILTER.replace("{username}", ldap3.utils.conv.escape_filter_chars(username))
        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[LDAP_DEPT_ATTRIBUTE, "displayName", "cn", "mail"],
        )

        if not conn.entries:
            logger.info("ldap_user_not_found", username=username)
            conn.unbind()
            return None

        user_entry = conn.entries[0]
        user_dn = str(user_entry.entry_dn)
        conn.unbind()

        # Step 3: Verify user's password with a separate bind
        user_conn = Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=False,
        )
        user_conn.open()

        if LDAP_STARTTLS and not LDAP_USE_SSL:
            user_conn.start_tls()

        if not user_conn.bind():
            logger.info("ldap_auth_failed", username=username)
            user_conn.unbind()
            return None

        user_conn.unbind()

        # Extract user attributes
        department = str(getattr(user_entry, LDAP_DEPT_ATTRIBUTE, "General"))
        if not department or department == "[]":
            department = "General"

        display_name = str(getattr(user_entry, "displayName", ""))
        if not display_name or display_name == "[]":
            display_name = str(getattr(user_entry, "cn", username))

        logger.info("ldap_auth_success", username=username, department=department)

        return {
            "dn": user_dn,
            "username": username,
            "department": department,
            "display_name": display_name,
        }

    except Exception as e:
        logger.error("ldap_auth_error", error=str(e), username=username)
        return None


async def ldap_authenticate_and_provision(
    username: str,
    password: str,
    session_factory,
) -> dict | None:
    """Authenticate via LDAP and auto-provision a gateway API key.

    If the user already has an active key (matched by ldap_dn), returns
    the existing key. Otherwise creates a new one.

    Returns: {"key": "...", "department": "...", "description": "..."} or None.
    """
    from auth import ApiKey, generate_key, hash_key
    from sqlalchemy import select

    user_info = ldap_authenticate(username, password)
    if user_info is None:
        return None

    ldap_dn = user_info["dn"]
    department = user_info["department"]
    display_name = user_info["display_name"]

    async with session_factory() as session:
        # Check for existing key by LDAP DN
        result = await session.execute(
            select(ApiKey).filter(
                ApiKey.ldap_dn == ldap_dn,
                ApiKey.active == True,  # noqa: E712
            )
        )
        existing = result.scalars().first()

        if existing:
            # Return existing key (re-fetch the raw key if we have it,
            # otherwise generate a new one and update)
            if existing.key:
                return {
                    "key": existing.key,
                    "department": existing.department,
                    "description": existing.description,
                    "provisioned": False,
                }
            else:
                # Key was hashed only — generate a new one
                new_key = generate_key()
                existing.key = new_key
                existing.key_hash = hash_key(new_key)
                existing.key_prefix = new_key[:8]
                existing.department = department  # Update in case department changed
                await session.commit()
                return {
                    "key": new_key,
                    "department": department,
                    "description": existing.description,
                    "provisioned": False,
                }

        # Create new key
        new_key = generate_key()
        api_key = ApiKey(
            key=new_key,
            key_hash=hash_key(new_key),
            key_prefix=new_key[:8],
            department=department,
            description=f"{display_name} (LDAP: {username})",
            ldap_dn=ldap_dn,
            active=True,
        )
        session.add(api_key)
        await session.commit()

        logger.info("ldap_key_provisioned", username=username, department=department)
        return {
            "key": new_key,
            "department": department,
            "description": api_key.description,
            "provisioned": True,
        }
