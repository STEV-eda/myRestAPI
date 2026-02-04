"""
OAuth2/JWT Authentifizierungsmodul.
Unterstützt lokale JWT-Validierung und Token-Introspection.
"""
import logging
from functools import wraps
from typing import Optional, Tuple, Dict, Any

import requests
from flask import request, jsonify, g, current_app
from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

logger = logging.getLogger(__name__)


class OAuth2Validator:
    """OAuth2 Token Validator mit JWKS-Caching"""
    
    def __init__(self, config):
        self.config = config
        self._jwks_cache: Optional[Dict] = None
    
    def get_jwks(self) -> Optional[Dict]:
        """Holt JWKS mit Caching"""
        if self._jwks_cache is None:
            try:
                response = requests.get(self.config.JWKS_URI, timeout=10)
                response.raise_for_status()
                self._jwks_cache = response.json()
                logger.info(f"JWKS geladen: {len(self._jwks_cache.get('keys', []))} Schlüssel")
            except requests.RequestException as e:
                logger.error(f"JWKS-Abruf fehlgeschlagen: {e}")
                return None
        return self._jwks_cache
    
    def clear_jwks_cache(self) -> None:
        """Leert den JWKS-Cache (z.B. bei Key Rotation)"""
        self._jwks_cache = None
        logger.info("JWKS-Cache geleert")
    
    def validate_token_locally(self, token: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Validiert JWT lokal mit JWKS"""
        jwks = self.get_jwks()
        if not jwks:
            return None, "JWKS nicht verfügbar"
        
        try:
            # Header lesen für Key-ID
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            # Passenden Schlüssel finden
            rsa_key = None
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    rsa_key = key
                    break
            
            if not rsa_key:
                # Cache leeren und erneut versuchen (Key Rotation)
                self.clear_jwks_cache()
                jwks = self.get_jwks()
                if jwks:
                    for key in jwks.get("keys", []):
                        if key.get("kid") == kid:
                            rsa_key = key
                            break
                
                if not rsa_key:
                    return None, f"Schlüssel nicht gefunden (kid={kid})"
            
            # Token dekodieren
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                issuer=self.config.ISSUER,
                options={
                    "verify_at_hash": False,
                    "verify_aud": False
                }
            )
            
            # Audience prüfen
            aud = payload.get("aud", [])
            if isinstance(aud, str):
                aud = [aud]
            
            if self.config.KEYCLOAK_CLIENT_ID not in aud:
                return None, f"Ungültige Audience: {aud}"
            
            return payload, None
            
        except ExpiredSignatureError:
            return None, "Token abgelaufen"
        except JWTClaimsError as e:
            return None, f"Ungültige Claims: {e}"
        except JWTError as e:
            return None, f"Token ungültig: {e}"
        except Exception as e:
            logger.exception("Unerwarteter Validierungsfehler")
            return None, f"Validierungsfehler: {e}"
    
    def validate_token_introspection(self, token: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Validiert Token via Introspection-Endpoint"""
        try:
            response = requests.post(
                self.config.INTROSPECTION_ENDPOINT,
                data={"token": token},
                auth=(self.config.KEYCLOAK_CLIENT_ID, self.config.KEYCLOAK_CLIENT_SECRET),
                timeout=10
            )
            response.raise_for_status()
            result = response.json()
            
            if result.get("active"):
                return result, None
            return None, "Token nicht aktiv"
            
        except requests.RequestException as e:
            return None, f"Introspection fehlgeschlagen: {e}"
    
    def validate(self, token: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Validiert Token (lokal mit Fallback auf Introspection)"""
        # Zuerst lokal versuchen (schneller)
        payload, error = self.validate_token_locally(token)
        
        if error:
            logger.debug(f"Lokale Validierung fehlgeschlagen: {error}")
            # Fallback auf Introspection
            payload, error = self.validate_token_introspection(token)
        
        return payload, error


# Globaler Validator (wird in app.py initialisiert)
oauth_validator: Optional[OAuth2Validator] = None


def init_oauth(config) -> OAuth2Validator:
    """Initialisiert den OAuth2 Validator"""
    global oauth_validator
    oauth_validator = OAuth2Validator(config)
    return oauth_validator


def require_oauth(f):
    """Decorator: Erfordert gültiges OAuth2-Token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        
        if not auth_header:
            logger.warning(f"Kein Auth-Header: {request.method} {request.path}")
            return jsonify({
                "error": "Unauthorized",
                "message": "Authorization-Header fehlt"
            }), 401
        
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({
                "error": "Unauthorized",
                "message": "Ungültiges Authorization-Format (erwartet: Bearer <token>)"
            }), 401
        
        token = parts[1]
        
        if oauth_validator is None:
            logger.error("OAuth Validator nicht initialisiert")
            return jsonify({
                "error": "Internal Server Error",
                "message": "Authentifizierung nicht konfiguriert"
            }), 500
        
        payload, error = oauth_validator.validate(token)
        
        if error:
            logger.warning(f"Token-Validierung fehlgeschlagen: {error}")
            return jsonify({
                "error": "Unauthorized",
                "message": error
            }), 401
        
        # Token-Daten im Request-Context speichern
        g.token_data = payload
        g.user = payload.get("preferred_username") or payload.get("client_id")
        g.roles = payload.get("realm_access", {}).get("roles", [])
        
        return f(*args, **kwargs)
    
    return decorated


def require_role(required_role: str):
    """Decorator: Erfordert bestimmte Rolle"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token_data = getattr(g, 'token_data', None)
            
            if not token_data:
                return jsonify({
                    "error": "Forbidden",
                    "message": "Keine Token-Daten"
                }), 403
            
            roles = token_data.get("realm_access", {}).get("roles", [])
            
            if required_role not in roles:
                logger.warning(
                    f"Zugriff verweigert: Benutzer {g.user} hat Rolle '{required_role}' nicht"
                )
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Rolle '{required_role}' erforderlich"
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_any_role(*required_roles):
    """Decorator: Erfordert mindestens eine der angegebenen Rollen"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token_data = getattr(g, 'token_data', None)
            
            if not token_data:
                return jsonify({
                    "error": "Forbidden",
                    "message": "Keine Token-Daten"
                }), 403
            
            roles = set(token_data.get("realm_access", {}).get("roles", []))
            
            if not roles.intersection(required_roles):
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Eine dieser Rollen erforderlich: {required_roles}"
                }), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator
