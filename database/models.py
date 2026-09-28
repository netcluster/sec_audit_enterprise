"""
SEC-AUDIT ENTERPRISE - Modelos de Base de Datos PostgreSQL (SQLAlchemy)
Definición de tablas relacionales para Alcances (RoE), Activos, Escaneos y Hallazgos.
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime, ForeignKey, Enum
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class ScopeModel(Base):
    __tablename__ = "scopes"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    scope_type = Column(String(64), nullable=False)  # cloud_azure, cloud_oci, network, web_dast
    target = Column(Text, nullable=False)
    environment = Column(String(128), nullable=False)
    status = Column(String(32), default="authorized")  # authorized, suspended, expired
    authorized_by = Column(String(255), nullable=False)
    authorized_until = Column(DateTime, nullable=False)
    scan_window = Column(String(255), nullable=False)
    rate_limit = Column(String(128), default="50 req/s")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scans = relationship("ScanTaskModel", back_populates="scope", cascade="all, delete-orphan")
    findings = relationship("FindingModel", back_populates="scope", cascade="all, delete-orphan")


class ScanTaskModel(Base):
    __tablename__ = "scan_tasks"

    id = Column(String(64), primary_key=True, index=True)
    scope_id = Column(String(64), ForeignKey("scopes.id"), nullable=False)
    scan_type = Column(String(64), nullable=False)
    status = Column(String(32), default="pending")  # pending, running, completed, failed
    progress = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    results_summary = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scope = relationship("ScopeModel", back_populates="scans")


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True, index=True)
    scope_id = Column(String(64), ForeignKey("scopes.id"), nullable=False)
    vector = Column(String(64), nullable=False)  # cloud_azure, cloud_oci, network, web_dast
    resource = Column(String(255), nullable=False)
    resource_type = Column(String(128), nullable=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss = Column(Float, default=0.0)
    category = Column(String(128), nullable=True)
    control_benchmark = Column(String(255), nullable=True)
    cve_cwe = Column(String(64), nullable=True)
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    status = Column(String(32), default="open")  # open, in_remediation, verified_closed, accepted_risk
    detected_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scope = relationship("ScopeModel", back_populates="findings")
