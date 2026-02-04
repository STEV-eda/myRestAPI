"""
Datenbankmodul mit Connection Pooling.
Verwendet psycopg2 ThreadedConnectionPool für Thread-Sicherheit.
"""
import logging
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

import psycopg2
from psycopg2 import pool, DatabaseError, OperationalError

logger = logging.getLogger(__name__)


class DatabasePool:
    """Thread-safe Database Connection Pool"""
    
    _instance: Optional['DatabasePool'] = None
    _pool: Optional[pool.ThreadedConnectionPool] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def init_pool(
        self, 
        dbname: str, 
        user: str, 
        password: str, 
        host: str,
        port: str = "5432",
        minconn: int = 1, 
        maxconn: int = 10
    ) -> None:
        """Initialisiert den Connection Pool"""
        if self._pool is not None:
            logger.warning("Pool bereits initialisiert")
            return
            
        try:
            self._pool = pool.ThreadedConnectionPool(
                minconn=minconn,
                maxconn=maxconn,
                dbname=dbname,
                user=user,
                password=password,
                host=host,
                port=port
            )
            logger.info(f"Datenbankpool initialisiert: {minconn}-{maxconn} Verbindungen")
        except OperationalError as e:
            logger.error(f"Datenbankverbindung fehlgeschlagen: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """Context Manager für Datenbankverbindungen"""
        if self._pool is None:
            raise RuntimeError("Datenbankpool nicht initialisiert")
        
        conn = None
        try:
            conn = self._pool.getconn()
            yield conn
        except DatabaseError as e:
            if conn:
                conn.rollback()
            logger.error(f"Datenbankfehler: {e}")
            raise
        finally:
            if conn:
                self._pool.putconn(conn)
    
    def close_pool(self) -> None:
        """Schließt alle Verbindungen"""
        if self._pool:
            self._pool.closeall()
            self._pool = None
            logger.info("Datenbankpool geschlossen")
    
    def health_check(self) -> Dict[str, Any]:
        """Führt einen Health Check der Datenbank durch"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    return {"status": "healthy", "message": "Datenbankverbindung OK"}
        except Exception as e:
            return {"status": "unhealthy", "message": str(e)}


# Singleton-Instanz
db_pool = DatabasePool()


class ActorRepository:
    """Repository für Actor-Datenbankoperationen"""
    
    def __init__(self, database: DatabasePool):
        self.db = database
    
    def get_all(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Holt alle Schauspieler mit Pagination"""
        with self.db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT actor_id, first_name, last_name, last_update 
                    FROM actor 
                    ORDER BY actor_id 
                    LIMIT %s OFFSET %s
                    """,
                    (limit, offset)
                )
                rows = cur.fetchall()
                return [self._row_to_dict(row) for row in rows]
    
    def get_by_id(self, actor_id: int) -> Optional[Dict[str, Any]]:
        """Holt einen Schauspieler nach ID"""
        with self.db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT actor_id, first_name, last_name, last_update 
                    FROM actor 
                    WHERE actor_id = %s
                    """,
                    (actor_id,)
                )
                row = cur.fetchone()
                return self._row_to_dict(row) if row else None
    
    def get_count(self) -> int:
        """Gibt die Gesamtanzahl der Schauspieler zurück"""
        with self.db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM actor")
                return cur.fetchone()[0]
    
    def search_by_name(self, name: str) -> List[Dict[str, Any]]:
        """Sucht Schauspieler nach Name"""
        with self.db.get_connection() as conn:
            with conn.cursor() as cur:
                search_term = f"%{name}%"
                cur.execute(
                    """
                    SELECT actor_id, first_name, last_name, last_update 
                    FROM actor 
                    WHERE first_name ILIKE %s OR last_name ILIKE %s
                    ORDER BY last_name, first_name
                    """,
                    (search_term, search_term)
                )
                rows = cur.fetchall()
                return [self._row_to_dict(row) for row in rows]
    
    @staticmethod
    def _row_to_dict(row: tuple) -> Dict[str, Any]:
        """Konvertiert eine Datenbankzeile in ein Dictionary"""
        return {
            "actor_id": row[0],
            "first_name": row[1],
            "last_name": row[2],
            "last_update": row[3].isoformat() if row[3] else None
        }
