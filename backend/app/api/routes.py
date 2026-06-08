"""
API Routes for MalLens.
"""
import os
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.config import settings
from app.core.database import get_db
from app.models.analysis import (
    Analysis, StaticResult, DynamicResult, IOC, Report,
    AnalysisStatus, ThreatLevel
)
from app.analysis.static_analyzer import StaticAnalyzer
from app.analysis.dynamic_analyzer import DynamicAnalyzer
from app.analysis.ioc_extractor import IOCExtractor
from app.analysis.report_generator import ReportGenerator

router = APIRouter(prefix="/api", tags=["analysis"])


@router.post("/upload")
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Upload a file for analysis."""
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Check file size
    content = await file.read()
    if len(content) > settings.MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum size: {settings.MAX_FILE_SIZE // (1024*1024)}MB")

    # Check extension
    ext = Path(file.filename).suffix.lower()
    if ext and ext not in settings.ALLOWED_EXTENSIONS:
        # Allow files without extensions too
        pass

    # Generate analysis ID
    analysis_id = str(uuid.uuid4())

    # Compute hashes
    md5_hash = hashlib.md5(content).hexdigest()
    sha1_hash = hashlib.sha1(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()

    # Save file
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)
    file_path = upload_dir / f"{analysis_id}_{file.filename}"
    with open(file_path, "wb") as f:
        f.write(content)

    # Create analysis record
    analysis = Analysis(
        id=analysis_id,
        file_name=file.filename,
        file_hash_md5=md5_hash,
        file_hash_sha1=sha1_hash,
        file_hash_sha256=sha256_hash,
        file_size=len(content),
        file_type=ext or "unknown",
        mime_type=file.content_type,
        status=AnalysisStatus.PENDING,
        created_at=datetime.utcnow(),
    )
    db.add(analysis)
    await db.flush()

    # Start analysis in background
    background_tasks.add_task(run_analysis, analysis_id, str(file_path))

    return {
        "analysis_id": analysis_id,
        "file_name": file.filename,
        "file_size": len(content),
        "sha256": sha256_hash,
        "status": "pending",
        "message": "File uploaded successfully. Analysis started.",
    }


@router.get("/status/{analysis_id}")
async def get_status(analysis_id: str, db: AsyncSession = Depends(get_db)):
    """Get analysis status."""
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()

    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return {
        "analysis_id": analysis.id,
        "file_name": analysis.file_name,
        "status": analysis.status.value if analysis.status else "unknown",
        "threat_level": analysis.threat_level.value if analysis.threat_level else "unknown",
        "threat_score": analysis.threat_score,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        "started_at": analysis.started_at.isoformat() if analysis.started_at else None,
        "completed_at": analysis.completed_at.isoformat() if analysis.completed_at else None,
        "error_message": analysis.error_message,
    }


@router.get("/report/{analysis_id}")
async def get_report(analysis_id: str, db: AsyncSession = Depends(get_db)):
    """Get full analysis report."""
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()

    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Get static results
    static_result = await db.execute(
        select(StaticResult).where(StaticResult.analysis_id == analysis_id)
    )
    static = static_result.scalar_one_or_none()

    # Get dynamic results
    dynamic_result = await db.execute(
        select(DynamicResult).where(DynamicResult.analysis_id == analysis_id)
    )
    dynamic = dynamic_result.scalar_one_or_none()

    # Get IOCs
    iocs_result = await db.execute(
        select(IOC).where(IOC.analysis_id == analysis_id)
    )
    iocs = iocs_result.scalars().all()

    # Get report
    report_result = await db.execute(
        select(Report).where(Report.analysis_id == analysis_id)
    )
    report = report_result.scalar_one_or_none()

    return {
        "analysis": {
            "id": analysis.id,
            "file_name": analysis.file_name,
            "file_size": analysis.file_size,
            "file_type": analysis.file_type,
            "status": analysis.status.value if analysis.status else "unknown",
            "threat_level": analysis.threat_level.value if analysis.threat_level else "unknown",
            "threat_score": analysis.threat_score,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
            "completed_at": analysis.completed_at.isoformat() if analysis.completed_at else None,
        },
        "static": {
            "hashes": {
                "md5": analysis.file_hash_md5,
                "sha1": analysis.file_hash_sha1,
                "sha256": analysis.file_hash_sha256,
            },
            "file_type_detail": static.file_type_detail if static else None,
            "architecture": static.architecture if static else None,
            "entropy": static.entropy if static else None,
            "is_packed": static.is_packed if static else None,
            "packer": static.packer if static else None,
            "imports": static.imports if static else [],
            "suspicious_imports": static.suspicious_imports if static else [],
            "interesting_strings": static.interesting_strings if static else [],
            "urls_found": static.urls_found if static else [],
            "ips_found": static.ips_found if static else [],
            "yara_matches": static.yara_matches if static else [],
            "sections": static.sections if static else [],
        } if static else None,
        "dynamic": {
            "processes_created": dynamic.processes_created if dynamic else [],
            "process_tree": dynamic.process_tree if dynamic else [],
            "files_created": dynamic.files_created if dynamic else [],
            "files_modified": dynamic.files_modified if dynamic else [],
            "files_deleted": dynamic.files_deleted if dynamic else [],
            "registry_keys_created": dynamic.registry_keys_created if dynamic else [],
            "registry_keys_modified": dynamic.registry_keys_modified if dynamic else [],
            "dns_queries": dynamic.dns_queries if dynamic else [],
            "http_requests": dynamic.http_requests if dynamic else [],
            "tcp_connections": dynamic.tcp_connections if dynamic else [],
            "behavior_tags": dynamic.behavior_tags if dynamic else [],
            "mitre_techniques": dynamic.mitre_techniques if dynamic else [],
            "signatures_matched": dynamic.signatures_matched if dynamic else [],
            "behavior_timeline": dynamic.behavior_timeline if dynamic else [],
            "execution_duration": dynamic.execution_duration if dynamic else None,
        } if dynamic else None,
        "iocs": [
            {
                "id": ioc.id,
                "type": ioc.ioc_type,
                "value": ioc.value,
                "context": ioc.context,
                "severity": ioc.severity,
                "confidence": ioc.confidence,
                "source": ioc.ti_source,
            }
            for ioc in iocs
        ],
        "report": {
            "executive_summary": report.executive_summary if report else None,
            "detailed_analysis": report.detailed_analysis if report else None,
            "recommendations": report.recommendations if report else None,
            "risk_assessment": report.risk_assessment if report else None,
            "mitre_mapping": report.mitre_mapping if report else [],
            "generated_at": report.generated_at.isoformat() if report and report.generated_at else None,
            "generator": report.generator if report else None,
        } if report else None,
    }


@router.get("/queue")
async def get_queue(db: AsyncSession = Depends(get_db)):
    """Get list of recent analyses."""
    result = await db.execute(
        select(Analysis).order_by(desc(Analysis.created_at)).limit(50)
    )
    analyses = result.scalars().all()

    return {
        "analyses": [
            {
                "id": a.id,
                "file_name": a.file_name,
                "file_size": a.file_size,
                "file_type": a.file_type,
                "status": a.status.value if a.status else "unknown",
                "threat_level": a.threat_level.value if a.threat_level else "unknown",
                "threat_score": a.threat_score,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "completed_at": a.completed_at.isoformat() if a.completed_at else None,
            }
            for a in analyses
        ],
        "total": len(analyses),
    }


@router.get("/dashboard")
async def get_dashboard(db: AsyncSession = Depends(get_db)):
    """Get dashboard statistics."""
    # Total analyses
    total_result = await db.execute(select(func.count(Analysis.id)))
    total = total_result.scalar() or 0

    # By status
    status_result = await db.execute(
        select(Analysis.status, func.count(Analysis.id)).group_by(Analysis.status)
    )
    status_counts = {row[0].value if row[0] else "unknown": row[1] for row in status_result.all()}

    # By threat level
    threat_result = await db.execute(
        select(Analysis.threat_level, func.count(Analysis.id)).group_by(Analysis.threat_level)
    )
    threat_counts = {row[0].value if row[0] else "unknown": row[1] for row in threat_result.all()}

    # Recent analyses
    recent_result = await db.execute(
        select(Analysis).order_by(desc(Analysis.created_at)).limit(10)
    )
    recent = recent_result.scalars().all()

    # Top IOC types
    ioc_type_result = await db.execute(
        select(IOC.ioc_type, func.count(IOC.id)).group_by(IOC.ioc_type).order_by(desc(func.count(IOC.id))).limit(10)
    )
    top_ioc_types = [{"type": row[0], "count": row[1]} for row in ioc_type_result.all()]

    return {
        "total_analyses": total,
        "status_breakdown": status_counts,
        "threat_breakdown": threat_counts,
        "top_ioc_types": top_ioc_types,
        "recent_analyses": [
            {
                "id": a.id,
                "file_name": a.file_name,
                "status": a.status.value if a.status else "unknown",
                "threat_level": a.threat_level.value if a.threat_level else "unknown",
                "threat_score": a.threat_score,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in recent
        ],
    }


@router.delete("/analysis/{analysis_id}")
async def delete_analysis(analysis_id: str, db: AsyncSession = Depends(get_db)):
    """Delete an analysis and its results."""
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()

    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Delete uploaded file
    upload_dir = Path(settings.UPLOAD_DIR)
    for f in upload_dir.glob(f"{analysis_id}_*"):
        f.unlink(missing_ok=True)

    await db.delete(analysis)
    return {"message": "Analysis deleted successfully"}


# Background task for running analysis
async def run_analysis(analysis_id: str, file_path: str):
    """Run the full analysis pipeline as a background task."""
    from app.core.database import async_session

    async with async_session() as db:
        try:
            # Update status to processing
            result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
            analysis = result.scalar_one_or_none()
            if not analysis:
                return

            analysis.status = AnalysisStatus.PROCESSING
            analysis.started_at = datetime.utcnow()
            await db.commit()

            # Run static analysis
            static_analyzer = StaticAnalyzer(file_path)
            static_results = await static_analyzer.analyze()

            # Save static results
            static_record = StaticResult(
                analysis_id=analysis_id,
                file_type_detail=static_results.get("file_info", {}).get("detected_type"),
                architecture=static_results.get("file_info", {}).get("architecture"),
                entropy=static_results.get("entropy", {}).get("overall"),
                is_packed=str(static_results.get("is_packed", False)),
                packer=static_results.get("packer"),
                imports=static_results.get("imports", []),
                suspicious_imports=static_results.get("suspicious_imports", []),
                interesting_strings=static_results.get("strings", {}).get("interesting", []),
                urls_found=static_results.get("urls_found", []),
                ips_found=static_results.get("ips_found", []),
                yara_matches=static_results.get("yara_matches", []),
                sections=static_results.get("sections", []),
            )
            db.add(static_record)

            analysis.status = AnalysisStatus.STATIC_COMPLETE
            await db.commit()

            # Run dynamic analysis
            dynamic_analyzer = DynamicAnalyzer(file_path, static_results)
            dynamic_results = await dynamic_analyzer.analyze()

            # Save dynamic results
            dynamic_record = DynamicResult(
                analysis_id=analysis_id,
                processes_created=dynamic_results.get("processes_created", []),
                process_tree=dynamic_results.get("process_tree", []),
                files_created=dynamic_results.get("files_created", []),
                files_modified=dynamic_results.get("files_modified", []),
                files_deleted=dynamic_results.get("files_deleted", []),
                registry_keys_created=dynamic_results.get("registry_keys_created", []),
                registry_keys_modified=dynamic_results.get("registry_keys_modified", []),
                registry_keys_deleted=dynamic_results.get("registry_keys_deleted", []),
                dns_queries=dynamic_results.get("dns_queries", []),
                http_requests=dynamic_results.get("http_requests", []),
                tcp_connections=dynamic_results.get("tcp_connections", []),
                udp_connections=dynamic_results.get("udp_connections", []),
                behavior_tags=dynamic_results.get("behavior_tags", []),
                mitre_techniques=dynamic_results.get("mitre_techniques", []),
                signatures_matched=dynamic_results.get("signatures_matched", []),
                behavior_timeline=dynamic_results.get("behavior_timeline", []),
                execution_duration=dynamic_results.get("execution_duration"),
            )
            db.add(dynamic_record)

            analysis.status = AnalysisStatus.DYNAMIC_COMPLETE
            await db.commit()

            # Extract IOCs
            ioc_extractor = IOCExtractor(static_results, dynamic_results)
            iocs = await ioc_extractor.extract()

            for ioc_data in iocs:
                ioc_record = IOC(
                    analysis_id=analysis_id,
                    ioc_type=ioc_data["type"],
                    value=ioc_data["value"],
                    context=ioc_data.get("context"),
                    severity=ioc_data.get("severity", "medium"),
                    confidence=ioc_data.get("confidence", 0.5),
                    ti_source=ioc_data.get("source"),
                )
                db.add(ioc_record)

            await db.commit()

            # Generate report
            analysis_data = {
                "file_name": analysis.file_name,
                "file_size": analysis.file_size,
            }
            report_gen = ReportGenerator(analysis_data, static_results, dynamic_results, iocs)
            report_data = await report_gen.generate()

            report_record = Report(
                analysis_id=analysis_id,
                executive_summary=report_data.get("executive_summary", ""),
                detailed_analysis=report_data.get("detailed_analysis", ""),
                recommendations=report_data.get("recommendations", ""),
                risk_assessment=report_data.get("risk_assessment", ""),
                mitre_mapping=report_data.get("mitre_mapping", []),
                generator=report_data.get("generator", "template"),
            )
            db.add(report_record)

            # Calculate threat score
            threat_score = _calculate_threat_score(static_results, dynamic_results, iocs)
            analysis.threat_score = threat_score
            analysis.threat_level = _determine_threat_level(threat_score)
            analysis.status = AnalysisStatus.COMPLETED
            analysis.completed_at = datetime.utcnow()

            await db.commit()

        except Exception as e:
            # Update status to error
            result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
            analysis = result.scalar_one_or_none()
            if analysis:
                analysis.status = AnalysisStatus.ERROR
                analysis.error_message = str(e)
                await db.commit()


def _calculate_threat_score(static_results: dict, dynamic_results: dict, iocs: list) -> float:
    """Calculate overall threat score (0-100)."""
    score = 0.0

    # Static indicators
    suspicious_imports = static_results.get("suspicious_imports", [])
    score += min(len(suspicious_imports) * 3, 20)

    entropy = static_results.get("entropy", {}).get("overall", 0)
    if entropy > 7.5:
        score += 15
    elif entropy > 7.0:
        score += 10
    elif entropy > 6.5:
        score += 5

    if static_results.get("is_packed"):
        score += 10

    if static_results.get("yara_matches"):
        score += 15

    # Dynamic indicators
    signatures = dynamic_results.get("signatures_matched", [])
    for sig in signatures:
        if sig.get("severity") == "critical":
            score += 15
        elif sig.get("severity") == "high":
            score += 10
        elif sig.get("severity") == "medium":
            score += 5

    mitre = dynamic_results.get("mitre_techniques", [])
    score += min(len(mitre) * 5, 20)

    # IOC count
    score += min(len(iocs) * 2, 15)

    return min(score, 100.0)


def _determine_threat_level(score: float) -> ThreatLevel:
    """Determine threat level from score."""
    if score >= 80:
        return ThreatLevel.CRITICAL
    elif score >= 60:
        return ThreatLevel.HIGH
    elif score >= 40:
        return ThreatLevel.MEDIUM
    elif score >= 20:
        return ThreatLevel.LOW
    else:
        return ThreatLevel.CLEAN
