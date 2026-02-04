"""
Actors API - Produktionsreife Flask-Anwendung.
"""
import os
import sys
import json
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, request, g
from flask_swagger_ui import get_swaggerui_blueprint

from config import get_config
from database import db_pool, ActorRepository
from auth import init_oauth, require_oauth, require_role


def create_app(config=None):
    """Application Factory Pattern"""
    app = Flask(__name__)
    
    if config is None:
        config = get_config()
    
    app.config.from_object(config)
    configure_logging(app, config)
    
    # Datenbank initialisieren
    try:
        db_pool.init_pool(
            dbname=config.DB_NAME,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            host=config.DB_HOST,
            port=config.DB_PORT,
            minconn=config.DB_MIN_CONNECTIONS,
            maxconn=config.DB_MAX_CONNECTIONS
        )
    except Exception as e:
        app.logger.error(f"DB-Init fehlgeschlagen: {e}")
        if not config.TESTING:
            sys.exit(1)
    
    init_oauth(config)
    app.actor_repo = ActorRepository(db_pool)
    
    # Swagger UI
    swagger_bp = get_swaggerui_blueprint(
        '/swagger', '/openapi.json',
        config={'app_name': config.API_TITLE, 'persistAuthorization': True}
    )
    app.register_blueprint(swagger_bp, url_prefix='/swagger')
    
    register_error_handlers(app)
    register_request_hooks(app)
    app.api_config = config
    
    return app


def configure_logging(app, config):
    log_level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)
    formatter = logging.Formatter(config.LOG_FORMAT)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    
    if not config.DEBUG and not config.TESTING:
        os.makedirs('logs', exist_ok=True)
        file_handler = RotatingFileHandler('logs/api.log', maxBytes=10485760, backupCount=10)
        file_handler.setFormatter(formatter)
        app.logger.addHandler(file_handler)
    
    app.logger.addHandler(console_handler)
    app.logger.setLevel(log_level)
    logging.getLogger('werkzeug').setLevel(logging.WARNING)


def register_error_handlers(app):
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad Request", "message": str(error.description)}), 400
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Not Found", "message": "Ressource nicht gefunden"}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.exception("Interner Serverfehler")
        return jsonify({"error": "Internal Server Error"}), 500


def register_request_hooks(app):
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        if app.config.get('DEBUG'):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
        return response


app = create_app()


@app.route('/')
def index():
    return jsonify({
        "name": app.api_config.API_TITLE,
        "version": app.api_config.API_VERSION,
        "documentation": "/swagger",
        "health": "/health"
    })


@app.route('/openapi.json')
def openapi_spec():
    openapi_path = os.path.join(os.path.dirname(__file__), app.api_config.OPENAPI_FILE)
    try:
        with open(openapi_path, 'r', encoding='utf-8') as f:
            return jsonify(json.load(f))
    except FileNotFoundError:
        return jsonify({"error": "OpenAPI-Datei nicht gefunden"}), 404


@app.route('/health')
@app.route('/health/live')
def health_live():
    return jsonify({"status": "healthy"})


@app.route('/health/ready')
def health_ready():
    db_status = db_pool.health_check()
    status_code = 200 if db_status["status"] == "healthy" else 503
    return jsonify({"status": "ready" if status_code == 200 else "not_ready", "checks": {"database": db_status}}), status_code


@app.route('/api/actors')
@require_oauth
def get_actors():
    try:
        limit = min(max(1, request.args.get('limit', 100, type=int)), 1000)
        offset = max(0, request.args.get('offset', 0, type=int))
        search = request.args.get('search', '', type=str)
        
        actors = app.actor_repo.search_by_name(search) if search else app.actor_repo.get_all(limit=limit, offset=offset)
        total = app.actor_repo.get_count()
        
        return jsonify({"data": actors, "meta": {"total": total, "limit": limit, "offset": offset, "count": len(actors)}})
    except Exception as e:
        app.logger.exception("Fehler beim Abrufen der Schauspieler")
        return jsonify({"error": "Datenbankfehler"}), 500


@app.route('/api/actors/<int:actor_id>')
@require_oauth
def get_actor(actor_id):
    try:
        actor = app.actor_repo.get_by_id(actor_id)
        if actor:
            return jsonify(actor)
        return jsonify({"error": "Not Found", "message": f"Schauspieler {actor_id} nicht gefunden"}), 404
    except Exception as e:
        return jsonify({"error": "Datenbankfehler"}), 500


@app.route('/api/token-info')
@require_oauth
def token_info():
    return jsonify({
        "user": g.user,
        "roles": g.roles,
        "issuer": g.token_data.get("iss"),
        "expires_at": g.token_data.get("exp"),
        "client_id": g.token_data.get("client_id") or g.token_data.get("azp")
    })


@app.route('/api/admin/actors', methods=['DELETE'])
@require_oauth
@require_role('api-admin')
def admin_endpoint():
    return jsonify({"message": "Admin-Zugriff gewährt", "user": g.user})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
