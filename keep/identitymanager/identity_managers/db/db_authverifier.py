import os

import jwt
from fastapi import HTTPException

from keep.api.core.db import create_user, user_exists
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.authverifierbase import AuthVerifierBase
from keep.identitymanager.rbac import Admin as AdminRole
from keep.identitymanager.rbac import Roles, get_role_by_role_name


class DbAuthVerifier(AuthVerifierBase):
    """Handles authentication and authorization for single tenant mode"""

    _keycloak_jwks_client = None

    def _verify_keycloak_token(self, token: str) -> AuthenticatedEntity | None:
        """
        Optional "Sign in with Keycloak" on top of DB auth.

        Returns None when Keycloak is not configured or the token was not issued by it,
        so the regular DB token flow handles it. Keycloak users get the read-only role.
        """
        issuer = os.environ.get("KEYCLOAK_ISSUER", "").rstrip("/")
        if not issuer:
            return None
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return None
        if unverified.get("iss") != issuer:
            return None

        client_id = os.environ.get("KEYCLOAK_ID")
        try:
            if DbAuthVerifier._keycloak_jwks_client is None:
                DbAuthVerifier._keycloak_jwks_client = jwt.PyJWKClient(
                    f"{issuer}/protocol/openid-connect/certs"
                )
            signing_key = DbAuthVerifier._keycloak_jwks_client.get_signing_key_from_jwt(
                token
            )
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=issuer,
                # Keycloak access tokens carry the client in "azp", checked below
                options={"verify_aud": False},
            )
            audience = payload.get("aud") or []
            if isinstance(audience, str):
                audience = [audience]
            if client_id and payload.get("azp") != client_id and client_id not in audience:
                raise ValueError("Token was not issued for this client")
        except Exception:
            self.logger.exception("Failed to verify Keycloak token")
            raise HTTPException(status_code=401, detail="Invalid Keycloak token")

        email = payload.get("email") or payload.get("preferred_username")
        return AuthenticatedEntity(
            SINGLE_TENANT_UUID, email, None, Roles.READ_ONLY.value
        )

    def _verify_bearer_token(self, token: str) -> AuthenticatedEntity:
        keycloak_entity = self._verify_keycloak_token(token)
        if keycloak_entity:
            if not get_role_by_role_name(keycloak_entity.role).has_scopes(self.scopes):
                raise HTTPException(
                    status_code=403,
                    detail="You don't have the required permissions to access this resource",
                )
            return keycloak_entity

        # validate the token
        jwt_secret = os.environ.get("KEEP_JWT_SECRET", "jwtsecret")
        # if default
        if jwt_secret == "jwtsecret":
            self.logger.warning(
                "KEEP_JWT_SECRET environment variable is not set, using default value. Should be set in production."
            )

        try:
            payload = jwt.decode(
                token,
                jwt_secret,
                algorithms="HS256",
            )
            tenant_id = payload.get("tenant_id")
            email = payload.get("email")
            role_name = payload.get(
                "role", AdminRole.get_name()
            )  # default to admin for backwards compatibility
            role = get_role_by_role_name(role_name)
        except Exception:
            self.logger.exception("Failed to decode JWT token")
            raise HTTPException(status_code=401, detail="Invalid JWT token")
        # validate scopes
        if not role.has_scopes(self.scopes):
            raise HTTPException(
                status_code=403,
                detail="You don't have the required permissions to access this resource",
            )
        return AuthenticatedEntity(tenant_id, email, None, role_name)

    # create user for auto-provisioning
    def _provision_user(self, tenant_id, user_name, role):
        if not user_exists(tenant_id, user_name):
            create_user(tenant_id=tenant_id, username=user_name, role=role, password="")
