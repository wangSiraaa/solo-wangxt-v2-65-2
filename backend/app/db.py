"""SQLAlchemy models: neighbors, policies + ordered rules, snapshots, runs."""
from __future__ import annotations

import datetime as dt
from typing import List

from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
    create_engine, select, text as __sa_text,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session,
)

from .config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Neighbor(Base):
    __tablename__ = "neighbors"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    ip: Mapped[str] = mapped_column(String(64))
    family: Mapped[int] = mapped_column(Integer, default=4)
    asn: Mapped[int] = mapped_column(Integer, nullable=True)
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
    __table_args__ = (UniqueConstraint("policy_id", "seq", name="uq_policy_seq"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
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
    version: Mapped[int] = mapped_column(Integer)
    label: Mapped[str] = mapped_column(String(128), default="")
    payload: Mapped[dict] = mapped_column(JSON)
    frr_config: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="lab")

    policy: Mapped[Policy] = relationship(back_populates="snapshots")
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)


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


# ---------------------------------------------------------------------------
# Concurrent editing: working copies + persistent merge transactions
# ---------------------------------------------------------------------------

class WorkingCopy(Base):
    """
    One person's fork of an immutable baseline snapshot.

    The copy keeps:
      * base_snapshot_id   -- the immutable fork point (the merge BASE)
      * version            -- monotonic per-copy edit counter (every saved
                              edit increments it; used for optimistic checks)
      * payload            -- current edited policy body (v4/v6 planes)
      * ops                -- append-only edit operation log
    Edits never mutate any snapshot; commits produce a NEW mainline snapshot.
    """
    __tablename__ = "working_copies"

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128))
    editor: Mapped[str] = mapped_column(String(64), default="lab")
    base_snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"))
    version: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict] = mapped_column(JSON)
    ops: Mapped[list] = mapped_column(JSON, default=list)
    abandoned: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        UniqueConstraint("policy_id", "name", name="uq_policy_copy_name"),
    )


class MergeTransaction(Base):
    """
    A persisted three-way merge attempt.

    A row is created on the first PREVIEW and survives refreshes and server
    restarts: base/main/work payloads, the semantic plan, outstanding human
    decisions and the BASE snapshot are all stored.  Commit atomically
    creates exactly one successor snapshot (guarded by a partial unique
    index on committed_snapshot_id); abandoning deletes nothing that other
    branches point at.
    """
    __tablename__ = "merge_transactions"

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"))
    working_copy_id: Mapped[int] = mapped_column(
        ForeignKey("working_copies.id", ondelete="CASCADE"))
    base_snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"))
    main_snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"))
    status: Mapped[str] = mapped_column(
        String(16), default="open")   # open | committed | abandoned
    base_payload: Mapped[dict] = mapped_column(JSON)
    main_payload: Mapped[dict] = mapped_column(JSON)
    work_payload: Mapped[dict] = mapped_column(JSON)
    plan: Mapped[dict] = mapped_column(JSON, default=dict)
    resolutions: Mapped[dict] = mapped_column(JSON, default=dict)
    committed_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), default="lab")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow)
    committed_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime, nullable=True)


def init_db() -> None:
    Base.metadata.create_all(engine)
    # A committed merge points at exactly one successor snapshot, and each
    # snapshot is produced by at most one merge transaction (idempotency +
    # the "one successor version" concurrency guarantee).
    with engine.begin() as conn:
        if engine.dialect.name == "sqlite":
            conn.execute(__sa_text(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "uq_merge_committed_snapshot "
                "ON merge_transactions(committed_snapshot_id) "
                "WHERE committed_snapshot_id IS NOT NULL"))
        elif engine.dialect.name == "postgresql":
            conn.execute(__sa_text(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "uq_merge_committed_snapshot "
                "ON merge_transactions(committed_snapshot_id) "
                "WHERE committed_snapshot_id IS NOT NULL"))


def get_session() -> Session:
    return SessionLocal()
