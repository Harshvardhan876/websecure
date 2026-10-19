"""Users/Scan/Finding models per 02_TRD.md, plus save/retrieve helpers."""
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from db import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Scan(db.Model):
    __tablename__ = "scans"

    scan_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    target_url = db.Column(db.String(255), nullable=False)
    scan_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    security_score = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)

    findings = db.relationship(
        "Finding", backref="scan", cascade="all, delete-orphan", lazy="joined"
    )

    def to_dict(self):
        return {
            "scan_id": self.scan_id,
            "user_id": self.user_id,
            "target_url": self.target_url,
            "scan_date": self.scan_date.isoformat(),
            "security_score": self.security_score,
            "risk_level": self.risk_level,
            "findings": [f.to_dict() for f in self.findings],
        }


class Finding(db.Model):
    __tablename__ = "findings"

    finding_id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.scan_id"), nullable=False)
    header_name = db.Column(db.String(100))
    status = db.Column(db.String(20))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)

    def to_dict(self):
        return {
            "finding_id": self.finding_id,
            "header_name": self.header_name,
            "status": self.status,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
        }


class EmailAlreadyRegisteredError(ValueError):
    pass


def create_user(name, email, password):
    if User.query.filter_by(email=email).first() is not None:
        raise EmailAlreadyRegisteredError(f"'{email}' is already registered")

    user = User(name=name, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def get_user_by_email(email):
    return User.query.filter_by(email=email).first()


def authenticate(email, password):
    user = get_user_by_email(email)
    if user is not None and user.check_password(password):
        return user
    return None


def save_scan_result(scan_result, user_id=None):
    """Persist a scanner.scan(url) dict as a Scan + its Finding rows."""
    scan = Scan(
        user_id=user_id,
        target_url=scan_result["target_url"],
        security_score=scan_result["security_score"],
        risk_level=scan_result["risk_level"],
    )
    for f in scan_result["findings"]:
        scan.findings.append(Finding(**f))

    db.session.add(scan)
    db.session.commit()
    return scan


def claim_scans(scan_ids, user_id):
    """Move scans run before login (user_id NULL) into the account that just logged in or registered."""
    if scan_ids:
        Scan.query.filter(Scan.scan_id.in_(scan_ids), Scan.user_id.is_(None)).update(
            {"user_id": user_id}, synchronize_session=False
        )
        db.session.commit()


def get_scan_by_id(scan_id):
    return db.session.get(Scan, scan_id)


def get_recent_scans(limit=20):
    return Scan.query.order_by(Scan.scan_date.desc()).limit(limit).all()


def get_scans_for_user(user_id, limit=50):
    """Separate from get_recent_scans so a web route can never return another user's scans."""
    return (
        Scan.query.filter_by(user_id=user_id)
        .order_by(Scan.scan_date.desc())
        .limit(limit)
        .all()
    )
