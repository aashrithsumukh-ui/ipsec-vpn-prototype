from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import DateTime, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from ipsecguard.utils import DATA_DIR

DATABASE_URL = f"sqlite:///{DATA_DIR / 'results.db'}"
engine = create_engine(DATABASE_URL, future=True)


class Base(DeclarativeBase):
    pass


class AnalysisRecord(Base):
    __tablename__ = "analysis_results"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), primary_key=True)
    path: Mapped[str] = mapped_column(Text())
    payload_json: Mapped[str] = mapped_column(Text())
    created_at: Mapped[datetime] = mapped_column(
        DateTime(), default=lambda: datetime.now(UTC).replace(tzinfo=None)
    )


class AnalysisRepository:
    def __init__(self) -> None:
        Base.metadata.create_all(engine)

    def save_report(self, report_id: str, kind: str, path: str, payload: dict) -> None:
        self.save_reports([(report_id, kind, path, payload)])

    def save_reports(self, reports: list[tuple[str, str, str, dict]]) -> None:
        with Session(engine) as session:
            for report_id, kind, path, payload in reports:
                session.merge(
                    AnalysisRecord(
                        id=report_id,
                        kind=kind,
                        path=path,
                        payload_json=json.dumps(payload, default=str),
                    )
                )
            session.commit()

    def get_report(self, report_id: str, kind: str) -> AnalysisRecord | None:
        with Session(engine) as session:
            return session.scalar(
                select(AnalysisRecord).where(
                    AnalysisRecord.id == report_id,
                    AnalysisRecord.kind == kind,
                )
            )

    def list_recent_reports(self, limit: int = 15) -> list[dict]:
        with Session(engine) as session:
            records = session.scalars(
                select(AnalysisRecord)
                .where(AnalysisRecord.kind == "technical")
                .order_by(AnalysisRecord.created_at.desc())
                .limit(limit)
            ).all()
            results = []
            for record in records:
                try:
                    payload = json.loads(record.payload_json)
                    results.append({
                        "id": record.id,
                        "created_at": record.created_at.isoformat() if record.created_at else "",
                        "score": payload.get("score", 0),
                        "flow_count": payload.get("session_summary", {}).get("flow_count", 0),
                        "traffic_label": payload.get("session_summary", {}).get("traffic_label", "N/A"),
                        "findings_count": len(payload.get("findings", [])),
                    })
                except Exception:
                    continue
            return results
