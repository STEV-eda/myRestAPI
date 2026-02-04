"""
Konfigurationsmanagement für die Actors API.
Unterstützt verschiedene Umgebungen (Development, Testing, Production).
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Basis-Konfiguration"""
    
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    
    # Datenbank
    DB_NAME = os.environ.get("db_name", "")
    DB_USER = os.environ.get("db_user", "")
    DB_PASSWORD = os.environ.get("db_password", "")
    DB_HOST = os.environ.get("db_host", "")
    DB_PORT = os.environ.get("db_port", "")
    DB_MIN_CONNECTIONS = int(os.environ.get("DB_MIN_CONNECTIONS", "1"))
    DB_MAX_CONNECTIONS = int(os.environ.get("DB_MAX_CONNECTIONS", "10"))
    
    # Keycloak / OAuth2
    KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "")
    KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "")
    KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "")
    KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET", "")
    
    # Abgeleitete OAuth2 URLs
    @property
    def ISSUER(self):
        return f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}"
    
    @property
    def JWKS_URI(self):
        return f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}/protocol/openid-connect/certs"
    
    @property
    def INTROSPECTION_ENDPOINT(self):
        return f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}/protocol/openid-connect/token/introspect"
    
    # Logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FORMAT = os.environ.get(
        "LOG_FORMAT", 
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # API
    API_TITLE = "Actors API"
    API_VERSION = "1.0.0"
    OPENAPI_FILE = os.environ.get("OPENAPI_FILE", "openapi.json")


class DevelopmentConfig(Config):
    """Entwicklungsumgebung"""
    DEBUG = True
    TESTING = False
    LOG_LEVEL = "DEBUG"


class TestingConfig(Config):
    """Testumgebung"""
    DEBUG = False
    TESTING = True
    DB_NAME = os.environ.get("", "")
    LOG_LEVEL = "DEBUG"


class ProductionConfig(Config):
    """Produktionsumgebung"""
    DEBUG = False
    TESTING = False
    LOG_LEVEL = "WARNING"
    
    def __init__(self):
        super().__init__()
        # Validiere kritische Konfiguration
        if self.SECRET_KEY == "dev-secret-key-change-in-production":
            raise ValueError("SECRET_KEY muss in Produktion gesetzt werden!")
        if not self.KEYCLOAK_CLIENT_SECRET:
            raise ValueError("KEYCLOAK_CLIENT_SECRET muss gesetzt werden!")


def get_config():
    """Gibt die Konfiguration basierend auf FLASK_ENV zurück"""
    env = os.environ.get("FLASK_ENV", "development").lower()
    
    configs = {
        "development": DevelopmentConfig,
        "testing": TestingConfig,
        "production": ProductionConfig
    }
    
    config_class = configs.get(env, DevelopmentConfig)
    return config_class()
