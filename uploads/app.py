"""
AI-Assisted Digital Forensics Investigation System
Main Flask Application Entry Point
"""

import os
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
import json
import uuid
import secrets
from datetime import datetime
from pathlib import Path
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, session, send_file, abort, g
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

from config import config, Config
from database import db, bcrypt, User, Case, Evidence, AnalysisResult, AIAnalysis, TimelineEvent, InvestigatorNote, AuditLog, EvidenceHash

# ── Module imports ────────────────────────────────────────
from modules.integrity_checker import compute_hashes, verify_integrity
from modules.evidence_parser import parse_evidence
from modules.email_forensics import analyze_email
from modules.browser_forensics import analyze_browser_history
from modules.timeline_engine import build_timeline
from modules.report_generator import generate_pdf_report


# ═══════════════════════════════════════════════════════════
#  APP FACTORY
# ═══════════════════════════════════════════════════════════

def create_app(config_name: str = "default") -> Flask:
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Init extensions
    db.init_app(app)
    bcrypt.init_app(app)
    csrf = CSRFProtect(app)

    login_manager = LoginManager(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access the forensics platform."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Ensure directories exist
    for folder in [
        app.config["UPLOAD_FOLDER"],
        app.config["EVIDENCE_FOLDER"],
        app.config["REPORTS_FOLDER"],
        str(Path(app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")).parent),
        app.config["ML_MODELS_FOLDER"],
    ]:
        os.makedirs(folder, exist_ok=True)

    # Register blueprints
    from routes.auth import auth_bp
    from routes.cases import cases_bp
    from routes.evidence import evidence_bp
    from routes.analysis import analysis_bp
    from routes.reports_api import reports_bp, api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(cases_bp, url_prefix="/cases")
    app.register_blueprint(evidence_bp, url_prefix="/evidence")
    app.register_blueprint(analysis_bp, url_prefix="/analysis")
    app.register_blueprint(reports_bp, url_prefix="/reports")
    app.register_blueprint(api_bp, url_prefix="/api")

    # ── Context processors ────────────────────────────────
    @app.context_processor
    def inject_globals():
        return {
            "now": datetime.utcnow(),
            "app_name": "ForensIQ",
        }

    # ── Main dashboard route ──────────────────────────────
    @app.route("/")
    @login_required
    def dashboard():
        total_cases = Case.query.filter_by(investigator_id=current_user.id).count()
        open_cases = Case.query.filter_by(investigator_id=current_user.id, status="open").count()
        total_evidence = db.session.query(Evidence).join(Case).filter(Case.investigator_id == current_user.id).count()
        flagged_evidence = db.session.query(Evidence).join(Case).filter(
            Case.investigator_id == current_user.id,
            Evidence.status == "flagged"
        ).count()

        recent_cases = Case.query.filter_by(investigator_id=current_user.id).order_by(Case.created_at.desc()).limit(5).all()
        recent_alerts = db.session.query(Evidence).join(Case).filter(
            Case.investigator_id == current_user.id,
            Evidence.status == "flagged"
        ).order_by(Evidence.uploaded_at.desc()).limit(8).all()

        # Build chart data
        case_types = db.session.query(Case.case_type, db.func.count(Case.id)).filter_by(
            investigator_id=current_user.id
        ).group_by(Case.case_type).all()

        risk_distribution = {
            "high": db.session.query(Evidence).join(Case).filter(
                Case.investigator_id == current_user.id, Evidence.risk_score >= 0.75).count(),
            "medium": db.session.query(Evidence).join(Case).filter(
                Case.investigator_id == current_user.id,
                Evidence.risk_score >= 0.45, Evidence.risk_score < 0.75).count(),
            "low": db.session.query(Evidence).join(Case).filter(
                Case.investigator_id == current_user.id, Evidence.risk_score < 0.45).count(),
        }

        return render_template(
            "dashboard.html",
            total_cases=total_cases,
            open_cases=open_cases,
            total_evidence=total_evidence,
            flagged_evidence=flagged_evidence,
            recent_cases=recent_cases,
            recent_alerts=recent_alerts,
            recent_activity=AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(10).all(),
            case_types=json.dumps(dict(case_types)),
            risk_distribution=json.dumps(risk_distribution),
        )

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(500)
    def server_error(e):
        return render_template("errors/500.html"), 500

    return app


# ═══════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════

def allowed_file(filename: str) -> bool:
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in Config.ALLOWED_EXTENSIONS
    )


def generate_case_id() -> str:
    now = datetime.utcnow()
    return f"CASE-{now.strftime('%Y%m')}-{secrets.token_hex(3).upper()}"


def generate_evidence_id() -> str:
    return f"EV-{secrets.token_hex(4).upper()}"


def log_audit(action: str, resource_type: str = None, resource_id: str = None, details: str = None):
    """Write an entry to the forensic audit trail."""
    try:
        log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            details=details,
            ip_address=request.remote_addr,
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        pass


# Make helpers available to blueprints
import builtins
builtins._forensiq_allowed_file = allowed_file
builtins._forensiq_generate_case_id = generate_case_id
builtins._forensiq_generate_evidence_id = generate_evidence_id
builtins._forensiq_log_audit = log_audit


# ═══════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════

app = create_app("development")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Create default admin if first run
        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                email="admin@forensiq.local",
                role="admin",
                full_name="System Administrator",
                badge_number="ADM-001",
                department="Cyber Forensics Division",
            )
            admin.set_password("Admin@ForensIQ2024")
            db.session.add(admin)
            db.session.commit()
            print("[+] Default admin created: admin / Admin@ForensIQ2024")
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)
