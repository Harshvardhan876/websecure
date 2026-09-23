"""Scan/Finding models per 02_TRD.md, plus save/retrieve helpers.

Users table is a separate Phase 3 sub-task (login/registration), not yet
built, so `Scan.user_id` has no ForeignKey constraint yet -- it is added
once the Users model exists.
"""
from datetime import datetime, timezone

from db import db


class Scan(db.Model):
    __tablename__ = "scans"

    scan_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
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


def get_scan_by_id(scan_id):
    return db.session.get(Scan, scan_id)


def get_recent_scans(limit=20):
    return Scan.query.order_by(Scan.scan_date.desc()).limit(limit).all()
