"""SQLAlchemy models: neighbors, policies + ordered rules, snapshots, runs."""
from __future__ import annotations

import datetime as dt
import uuid
from typing import List

from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
    create_engine, event, inspect, select, text,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session,
)

from .config import DATABASE_URL

connect_args = {"check_same_thread": False, "timeout": 30} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    @event.listens_for(engine, "begin")
    def _sqlite_immediate(conn):
        conn.exec_driver_sql("BEGIN IMMEDIATE")

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def new_rid() -> str:
    return f"r_{uuid.uuid4().hex[:12]}"


class Neighbor(Base):
    __tablename__ = "neighbors"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    ip: Mapped[str] = mapped_column(String(64))
    family: Mapped[int] = mapped_column(Integer, default=4)
    asn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    inbound_policy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    outbound_policy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    family: Mapped[int] = mapped_column(Integer, default=4)       # 4 or 6
    default_action: Mapped[str] = mapped_column(String(8), default="deny")
    description: Mapped[str] = mapped_column(String(256), default="")
    draft: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow)

    rules: Mapped[List["Rule"]] = relationship(
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="Rule.seq",
    )
    snapshots: Mapped[List["Snapshot"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan",
        order_by="Snapshot.version.desc()",
    )


class Rule(Base):
    __tablename__ = "rules"
    __table_args__ = (
        UniqueConstraint("policy_id", "seq", name="uq_policy_seq"),
        UniqueConstraint("policy_id", "rid", name="uq_policy_rid"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    rid: Mapped[str] = mapped_column(String(64), nullable=True, default=new_rid)
    seq: Mapped[int] = mapped_column(Integer)
    prefix: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(8))                  # permit/deny
    ge: Mapped[int | None] = mapped_column(Integer, nullable=True)
    le: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remark: Mapped[str] = mapped_column(String(256), default="")

    policy: Mapped[Policy] = relationship(back_populates="rules")


class Snapshot(Base):
    """
    Immutable configuration snapshot.  payload is the exact, replayable
    policy body: ordered rules + default action + family, plus FRR-rendered
    config and metadata.  Replays never depend on later edits.
    """
    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id", ondelete="SET NULL"), nullable=True)
    version: Mapped[int] = mapped_column(Integer)
    label: Mapped[str] = mapped_column(String(128), default="")
    payload: Mapped[dict] = mapped_column(JSON)
    frr_config: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="lab")
    created_by_workcopy_id: Mapped[int | None] = mapped_column(
        ForeignKey("workcopies.id", ondelete="SET NULL"), nullable=True)
    merge_info: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    policy: Mapped[Policy] = relationship(back_populates="snapshots")
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)


class WorkCopy(Base):
    """A private branch whose baseline and full edit history are durable."""
    __tablename__ = "workcopies"
    __table_args__ = (
        UniqueConstraint("policy_id", "name", name="uq_policy_workcopy"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128))
    created_by: Mapped[str] = mapped_column(String(64), default="lab")
    base_snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"))
    current_payload: Mapped[dict] = mapped_column(JSON)
    version: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="active")
    committed_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id", ondelete="SET NULL"), nullable=True, unique=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow)

    policy = relationship("Policy")
    base_snapshot = relationship("Snapshot", foreign_keys=[base_snapshot_id])
    operations: Mapped[List["WorkCopyOp"]] = relationship(
        back_populates="workcopy", cascade="all, delete-orphan",
        order_by="WorkCopyOp.version")
    merge_sessions: Mapped[List["MergeSession"]] = relationship(
        back_populates="workcopy", cascade="all, delete-orphan",
        order_by="MergeSession.id.desc()")


class WorkCopyOp(Base):
    """One append-only, optimistic-concurrency-controlled edit revision."""
    __tablename__ = "workcopy_ops"
    __table_args__ = (
        UniqueConstraint("workcopy_id", "version", name="uq_workcopy_version"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    workcopy_id: Mapped[int] = mapped_column(
        ForeignKey("workcopies.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    operation: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    workcopy = relationship("WorkCopy", back_populates="operations")


class MergeSession(Base):
    """Durable state for a semantic three-way preview/manual resolution."""
    __tablename__ = "merge_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    workcopy_id: Mapped[int] = mapped_column(
        ForeignKey("workcopies.id", ondelete="CASCADE"))
    base_snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"))
    main_snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"))
    status: Mapped[str] = mapped_column(String(16), default="conflict")
    version: Mapped[int] = mapped_column(Integer, default=1)
    analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    resolutions: Mapped[dict] = mapped_column(JSON, default=dict)
    candidate_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    committed_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id", ondelete="SET NULL"), nullable=True, unique=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow)

    workcopy = relationship("WorkCopy", back_populates="merge_sessions")


class Scenario(Base):
    """Saved replay bundle: from/to snapshots, probe inputs, observed results."""
    __tablename__ = "scenarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    from_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    to_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    probes: Mapped[list] = mapped_column(JSON, default=list)   # ordered prefix list
    results: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Run(Base):
    """One cross-validation run against a local FRR container."""
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    node: Mapped[str] = mapped_column(String(16), default="a")      # router-a/b
    status: Mapped[str] = mapped_column(String(16), default="ok")   # ok/mismatch/error
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


def _add_missing_columns() -> None:
    """Tiny forward-compatible migration for databases created before merges."""
    inspector = inspect(engine)
    if not inspector.has_table("snapshots"):
        return
    columns = {c["name"]: c for c in inspector.get_columns("snapshots")}
    with engine.begin() as conn:
        if "parent_id" not in columns:
            conn.execute(text("ALTER TABLE snapshots ADD COLUMN parent_id INTEGER"))
        if "created_by_workcopy_id" not in columns:
            conn.execute(text(
                "ALTER TABLE snapshots ADD COLUMN created_by_workcopy_id INTEGER"))
        if "merge_info" not in columns:
            conn.execute(text("ALTER TABLE snapshots ADD COLUMN merge_info JSON"))
    if inspector.has_table("rules"):
        rule_cols = {c["name"] for c in inspector.get_columns("rules")}
        if "rid" not in rule_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE rules ADD COLUMN rid VARCHAR(64)"))
                # SQLite and PostgreSQL both support a generated unique string
                # for rows created before stable rule identities existed.
                conn.execute(text(
                    "UPDATE rules SET rid = 'legacy-' || id WHERE rid IS NULL"))



def init_db() -> None:
    # Add columns to pre-existing tables first; create_all then creates the
    # new merge tables and current missing tables without dropping history.
    _add_missing_columns()
    Base.metadata.create_all(engine)
    _add_missing_columns()


def get_session() -> Session:
    return SessionLocal()
