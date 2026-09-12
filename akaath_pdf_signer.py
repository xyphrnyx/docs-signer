#!/usr/bin/env python3
"""AKaaTH PDF Postprocessor v1.0.0"""
from __future__ import annotations

import argparse
import base64
import copy
import getpass
import hashlib
import json
import os
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

APP_NAME = "AKaaTH PDF Postprocessor"
APP_VERSION = "1.0.0"
MANIFEST_NAME = "AKaaTH_PROVENANCE_MANIFEST"
MANIFEST_VERSION = "1.0.0"
MANIFEST_PROFILE = "APM-1"
DEFAULT_AUTHOR = "AKaaTH_dev"
DEFAULT_CONTACT = "alessamiau@icloud.com"
DEFAULT_KEY_ID = "AKaaTH-ED25519-2026-01"
DEFAULT_ENGINE_FAMILY = "AKaaTH_STRUCTURAL_ENGINES"
SIGNED_SUFFIX = "_AKaaTH_firmado"

LOCAL_MODES = ("declared", "hash", "sign-local", "auto")


class AKaaTHError(RuntimeError):
    """Expected application error."""


@dataclass(frozen=True)
class EngineProfile:
    engine_id: str
    name: str
    version: str
    classification: str
    function: str
    derived_from: str | None = None


ENGINE_PROFILES: dict[str, EngineProfile] = {
    "prompt-auditor": EngineProfile(
        engine_id="AKAATH-PEA-001",
        name="AUDITOR_ESTRUCTURAL_DE_PROMPTS",
        version="1.0.0",
        classification="PROMPT_ENGINEERING_AUDITOR_LEVEL_6",
        function="Auditoria, diagnostico, optimizacion y validacion estructural de prompts.",
        derived_from="MOTOR_ESTRUCTURACION_DOCUMENTAL_BETA5",
    ),
    "document-structurer": EngineProfile(
        engine_id="AKAATH-MED-BETA5",
        name="MOTOR_ESTRUCTURACION_DOCUMENTAL",
        version="BETA5",
        classification="DOCUMENT_STRUCTURING_ENGINE",
        function="Estructuracion, normalizacion, consolidacion y generacion documental.",
        derived_from=None,
    ),
    "general": EngineProfile(
        engine_id="AKAATH-DGE-001",
        name="GENERADOR_DOCUMENTAL_GENERAL",
        version="1.0.0",
        classification="GENERAL_DOCUMENT_ENGINE",
        function="Generacion y transformacion documental de proposito general.",
        derived_from=None,
    ),
}


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be", errors="strict")


def canonical_json_bytes(value: Any) -> bytes:
    def encode(item: Any) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int) and not isinstance(item, bool):
            return str(item)
        if isinstance(item, float):
            raise AKaaTHError("El manifiesto contiene un numero flotante. APM-1 exige enteros o strings.")
        if isinstance(item, str):
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, list):
            return "[" + ",".join(encode(v) for v in item) + "]"
        if isinstance(item, dict):
            if not all(isinstance(k, str) for k in item):
                raise AKaaTHError("Todas las claves JSON deben ser strings.")
            keys = sorted(item.keys(), key=_utf16_sort_key)
            return "{" + ",".join(f"{encode(key)}:{encode(item[key])}" for key in keys) + "}"
        raise AKaaTHError(f"Tipo no compatible con canonicalizacion: {type(item)!r}")

    return encode(value).encode("utf-8")


def resolve_local_mode(args: argparse.Namespace) -> tuple[str, Ed25519PrivateKey | None]:
    mode = args.mode
    private_path = Path(args.private_key).expanduser() if args.private_key else None

    if mode == "declared":
        return "declared", None
    if mode == "hash":
        return "hash", None
    if mode == "sign-local":
        if private_path is None:
            raise AKaaTHError("--private-key es obligatorio en modo sign-local.")
        pem = private_path.read_bytes() if private_path.exists() else b""
        password = resolve_password(args) if b"ENCRYPTED PRIVATE KEY" in pem else None
        return "sign-local", load_private_key(private_path, password)
    if mode == "auto":
        if private_path and private_path.exists():
            pem = private_path.read_bytes()
            password = resolve_password(args) if b"ENCRYPTED PRIVATE KEY" in pem else None
            return "sign-local", load_private_key(private_path, password)
        return "hash", None
    raise AKaaTHError(f"Modo no reconocido: {mode}")


def process_one_local(source_path: Path, args: argparse.Namespace) -> dict[str, Any]:
    if not source_path.exists() or not source_path.is_file():
        raise AKaaTHError(f"No existe el PDF: {source_path}")
    if source_path.suffix.lower() != ".pdf":
        raise AKaaTHError(f"El archivo no es PDF: {source_path}")
    if source_path.stem.endswith(SIGNED_SUFFIX):
        raise AKaaTHError("El archivo ya parece ser una salida AKaaTH firmada.")

    mode, private_key = resolve_local_mode(args)
    paths = output_paths(source_path, Path(args.output_dir).expanduser() if args.output_dir else None)
    if paths["pdf"].exists() and not args.overwrite:
        raise AKaaTHError(f"Ya existe {paths['pdf']}. Usa --overwrite para reemplazarla.")

    core = make_core_from_args(source_path, args)
    signature: str | None = None
    key_id: str | None = None
    fingerprint: str | None = None

    if mode == "declared":
        status = "DECLARED"
    elif mode == "hash":
        status = "HASHED_UNSIGNED"
    else:
        assert private_key is not None
        core_bytes = canonical_json_bytes(core)
        signature = b64url_encode(private_key.sign(core_bytes))
        key_id = args.key_id
        fingerprint = public_key_fingerprint(private_key.public_key())
        status = "CRYPTOGRAPHICALLY_SIGNED"

    manifest_document, core_bytes, core_digest = build_manifest_document(core, status=status, key_id=key_id, public_fingerprint=fingerprint, signature=signature)

    page_bytes = signature_page_bytes(manifest_document, source_sha256=core["source_integrity"]["value"], manifest_sha256=core_digest)
    append_signature_page(source_path, paths["pdf"], page_bytes)

    artifact_bytes = paths["pdf"].read_bytes()
    artifact_digest = sha256_bytes(artifact_bytes)
    artifact_signature: str | None = None

    if private_key is not None:
        artifact_signature = b64url_encode(private_key.sign(artifact_bytes))
        paths["sig"].write_text(artifact_signature + "\n", encoding="ascii")

    write_sha256_sidecar(paths["sha256"], artifact_digest, paths["pdf"].name)

    envelope = {
        **manifest_document,
        "artifact_integrity": {
            "filename": paths["pdf"].name,
            "algorithm": "SHA-256",
            "value": artifact_digest,
            "size_bytes": len(artifact_bytes),
        },
        "artifact_proof": {
            "status": ("CRYPTOGRAPHICALLY_SIGNED" if artifact_signature else "HASHED_UNSIGNED"),
            "signature_algorithm": "Ed25519" if artifact_signature else "NONE",
            "key_id": key_id,
            "public_key_fingerprint": fingerprint,
            "signature_encoding": "BASE64URL" if artifact_signature else "NONE",
            "signature": artifact_signature,
            "signed_scope": "FINAL_PDF_BYTES" if artifact_signature else None,
        },
    }
    write_json(paths["manifest"], envelope)

    return {
        "source": str(source_path),
        "mode_resolved": mode,
        "pdf": str(paths["pdf"]),
        "manifest": str(paths["manifest"]),
        "sha256": str(paths["sha256"]),
        "signature": str(paths["sig"]) if artifact_signature else None,
        "source_sha256": core["source_integrity"]["value"],
        "manifest_sha256": core_digest,
        "artifact_sha256": artifact_digest,
    }


def public_key_raw(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    return "SHA256:" + sha256_bytes(public_key_raw(public_key))


def save_keypair(
    private_path: Path,
    public_path: Path,
    key_id: str,
    password: bytes | None,
    overwrite: bool,
) -> dict[str, Any]:
    for path in (private_path, public_path):
        if path.exists() and not overwrite:
            raise AKaaTHError(f"Ya existe {path}. Usa --overwrite solo si realmente deseas reemplazarlo.")

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass

    raw = public_key_raw(public_key)
    registry_fragment = {
        "key_id": key_id,
        "owner": DEFAULT_AUTHOR,
        "status": "ACTIVE",
        "algorithm": "Ed25519",
        "public_key_encoding": "BASE64",
        "public_key": base64.b64encode(raw).decode("ascii"),
        "fingerprint_algorithm": "SHA-256",
        "public_key_fingerprint": public_key_fingerprint(public_key),
        "valid_from": datetime.now().astimezone().isoformat(timespec="seconds"),
        "valid_until": None,
        "revoked_at": None,
        "revocation_reason": None,
        "authorized_uses": [
            "CANONICAL_MANIFEST_SIGNATURE",
            "FINAL_PDF_ARTIFACT_SIGNATURE",
        ],
    }
    fragment_path = public_path.with_suffix(".registry-fragment.json")
    write_json(fragment_path, registry_fragment)
    return registry_fragment


def load_private_key(path: Path, password: bytes | None) -> Ed25519PrivateKey:
    if not path.exists():
        raise AKaaTHError(f"No existe la clave privada: {path}")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    except (TypeError, ValueError) as exc:
        raise AKaaTHError("No fue posible abrir la clave privada. Verifica la contrasena.") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AKaaTHError("La clave privada no es Ed25519.")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    if not path.exists():
        raise AKaaTHError(f"No existe la clave publica: {path}")
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except ValueError as exc:
        raise AKaaTHError("No fue posible abrir la clave publica.") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AKaaTHError("La clave publica no es Ed25519.")
    return key


def resolve_password(args: argparse.Namespace, *, confirm: bool = False) -> bytes | None:
    if getattr(args, "unencrypted", False):
        return None

    env_name = getattr(args, "password_env", None)
    if env_name:
        value = os.environ.get(env_name)
        if value is None:
            raise AKaaTHError(f"No existe la variable de entorno {env_name}.")
        return value.encode("utf-8")

    first = getpass.getpass("Contrasena de la clave privada: ")
    if not first:
        raise AKaaTHError("La contrasena no puede estar vacia.")
    if confirm:
        second = getpass.getpass("Repite la contrasena: ")
        if first != second:
            raise AKaaTHError("Las contrasenas no coinciden.")
    return first.encode("utf-8")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def default_document_id(engine_id: str) -> str:
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    return f"{engine_id}-{stamp}-{uuid.uuid4().hex[:8].upper()}"


def build_manifest_core(
    *,
    source_path: Path,
    source_sha256: str,
    source_size: int,
    engine: EngineProfile,
    operation_type: str,
    intervention_scope: list[str],
    author: str,
    contact: str,
    document_id: str,
    execution_id: str,
    generated_at: str,
    source_author: str | None,
    session_reference: str | None,
    registries: dict[str, str | None],
) -> dict[str, Any]:
    return {
        "specification": {
            "name": MANIFEST_NAME,
            "version": MANIFEST_VERSION,
            "profile": MANIFEST_PROFILE,
        },
        "authorship": {
            "principal_author": {"name": author, "contact": contact},
            "authorship_scope": [
                "system_architecture",
                "prompt_engineering",
                "intellectual_direction",
                "ai_assisted_research",
                "curation",
                "validation",
                "iterative_optimization",
            ],
            "development_method": {
                "type": "AI_ASSISTED_ITERATIVE_DEVELOPMENT",
                "statement": (
                    "Sistema disenado, dirigido, curado y refinado por AKaaTH_dev "
                    "mediante investigacion, analisis, pruebas y optimizaciones "
                    "realizadas durante multiples sesiones e iteraciones con "
                    "asistencia de modelos de inteligencia artificial."
                ),
            },
            "ai_assistance": {
                "role": "ANALYTICAL_AND_GENERATIVE_SUPPORT",
                "statement": (
                    "Los modelos de inteligencia artificial participaron como "
                    "instrumentos de investigacion, analisis, generacion, contraste "
                    "y optimizacion bajo direccion y curaduria humana."
                ),
            },
            "attribution_limits": {
                "statement": (
                    "La marca acredita arquitectura, metodologia, direccion "
                    "intelectual y procedencia tecnica. No atribuye automaticamente "
                    "a AKaaTH_dev el material fuente de usuarios o terceros."
                )
            },
        },
        "engine": {
            "family": DEFAULT_ENGINE_FAMILY,
            "engine_id": engine.engine_id,
            "name": engine.name,
            "version": engine.version,
            "classification": engine.classification,
            "function": engine.function,
            "lineage": {
                "derived_from": engine.derived_from,
                "previous_version": None,
            },
        },
        "operation": {
            "type": operation_type,
            "input_type": "PDF",
            "output_type": "PDF_WITH_APPENDED_PROVENANCE_PAGE",
            "intervention_scope": intervention_scope,
        },
        "generation": {
            "generated_at": generated_at,
            "document_id": document_id,
            "execution_id": execution_id,
            "session_reference": session_reference,
        },
        "source_provenance": {
            "source_type": "EXISTING_PDF",
            "source_author": source_author,
            "source_identifier": source_path.name,
            "transformation": (
                "Preservacion de las paginas fuente y adicion de una pagina final "
                "de autoria, procedencia e integridad."
            ),
        },
        "source_integrity": {
            "algorithm": "SHA-256",
            "value": source_sha256,
            "size_bytes": source_size,
        },
        "registries": registries,
        "canonicalization": {
            "method": "JSON_CANONICALIZATION_SCHEME_SAFE_SUBSET",
            "standard": "RFC_8785",
            "numeric_policy": "NO_FLOATS",
        },
    }


def build_manifest_document(
    core: dict[str, Any],
    *,
    status: str,
    key_id: str | None,
    public_fingerprint: str | None,
    signature: str | None,
) -> tuple[dict[str, Any], bytes, str]:
    core_bytes = canonical_json_bytes(core)
    core_digest = sha256_bytes(core_bytes)
    proof = {
        "status": status,
        "signature_algorithm": "Ed25519" if signature else "NONE",
        "key_id": key_id,
        "public_key_fingerprint": public_fingerprint,
        "signature_encoding": "BASE64URL" if signature else "NONE",
        "signature": signature,
        "signed_scope": (
            "CANONICAL_AKAATH_PROVENANCE_CORE"
            if signature
            else None
        ),
    }
    document = {
        "akaath_provenance_manifest": {
            **copy.deepcopy(core),
            "content_integrity": {
                "canonical_manifest_core": {
                    "algorithm": "SHA-256",
                    "value": core_digest,
                }
            },
            "cryptographic_proof": proof,
        }
    }
    return document, core_bytes, core_digest


def safe_text(value: Any) -> str:
    if value is None or value == "":
        return "NO DISPONIBLE"
    return str(value)


def compact_hash(value: str, width: int = 18) -> str:
    if len(value) <= width * 2:
        return value
    return f"{value[:width]}...{value[-width:]}"


def signature_page_bytes(
    manifest_document: dict[str, Any],
    *,
    source_sha256: str,
    manifest_sha256: str,
) -> bytes:
    manifest = manifest_document["akaath_provenance_manifest"]
    author = manifest["authorship"]["principal_author"]["name"]
    engine = manifest["engine"]
    operation = manifest["operation"]
    generation = manifest["generation"]
    proof = manifest["cryptographic_proof"]

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Autoria, procedencia e integridad AKaaTH",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("AKaaTHTitle", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=16, leading=19, textColor=colors.HexColor("#1f2937"), spaceAfter=10)
    subtitle_style = ParagraphStyle("AKaaTHSubtitle", parent=styles["Normal"], fontName="Helvetica", fontSize=9, leading=13, textColor=colors.HexColor("#4b5563"), spaceAfter=12)
    body_style = ParagraphStyle("AKaaTHBody", parent=styles["Normal"], fontName="Helvetica", fontSize=8.5, leading=12, alignment=TA_LEFT, textColor=colors.HexColor("#374151"))
    small_style = ParagraphStyle("AKaaTHSmall", parent=body_style, fontSize=7.7, leading=10.5, textColor=colors.HexColor("#6b7280"))

    story: list[Any] = [
        Paragraph("AUTORIA, PROCEDENCIA E INTEGRIDAD", title_style),
        Paragraph("Manifiesto visible incorporado por el posprocesador local AKaaTH. Las paginas fuente se conservan y esta pagina documenta la intervencion posterior.", subtitle_style),
    ]

    rows = [
        ("Arquitectura y direccion", author),
        ("Motor", f"{engine['name']} - {engine['version']}"),
        ("Intervencion", operation["type"]),
        ("Documento", generation["document_id"]),
        ("Generacion", generation["generated_at"]),
        ("Manifiesto", f"{MANIFEST_PROFILE} - v{MANIFEST_VERSION}"),
        ("SHA-256 PDF fuente", compact_hash(source_sha256)),
        ("SHA-256 manifiesto canonico", compact_hash(manifest_sha256)),
        ("Firma criptografica", " - ".join([safe_text(proof.get("status")), safe_text(proof.get("signature_algorithm")), safe_text(proof.get("key_id"))])),
        ("Huella de clave publica", compact_hash(safe_text(proof.get("public_key_fingerprint")))),
    ]

    table_data = [
        [Paragraph(f"<b>{label}</b>", body_style), Paragraph(value, body_style)]
        for label, value in rows
    ]
    table = Table(table_data, colWidths=[55 * mm, 118 * mm], repeatRows=0)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.45, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([table, Spacer(1, 10 * mm)])

    story.append(Paragraph("<b>Arquitectura, direccion intelectual, curaduria y evolucion iterativa: AKaaTH_dev.</b>", body_style))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("Desarrollo asistido por inteligencia artificial mediante investigacion, analisis, contraste, pruebas y optimizacion realizados durante multiples sesiones e iteraciones bajo direccion y curaduria humana.", body_style))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("Esta marca acredita la arquitectura, metodologia y procedencia tecnica del procesamiento. No atribuye automaticamente a AKaaTH_dev la autoria del material fuente proporcionado por usuarios o terceros.", small_style))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("El hash exacto del PDF resultante y, cuando corresponda, su firma Ed25519 se almacenan en archivos laterales .sha256 y .sig. No se imprime el hash final dentro del mismo PDF porque modificar el PDF para incluirlo cambiaria nuevamente dicho hash.", small_style))

    document.build(story)
    return buffer.getvalue()


def append_signature_page(source_path: Path, output_path: Path, page_pdf_bytes: bytes) -> None:
    try:
        source_reader = PdfReader(str(source_path))
    except Exception as exc:
        raise AKaaTHError(f"No fue posible leer el PDF fuente: {source_path}") from exc

    if source_reader.is_encrypted:
        try:
            result = source_reader.decrypt("")
        except Exception as exc:
            raise AKaaTHError("El PDF esta cifrado y no puede procesarse sin clave.") from exc
        if result == 0:
            raise AKaaTHError("El PDF esta cifrado y requiere contrasena.")

    page_reader = PdfReader(BytesIO(page_pdf_bytes))
    writer = PdfWriter()

    for page in source_reader.pages:
        writer.add_page(page)
    for page in page_reader.pages:
        writer.add_page(page)

    if source_reader.metadata:
        metadata = {str(key): str(value) for key, value in source_reader.metadata.items() if value is not None}
        metadata["/AKaaTHPostprocessor"] = f"{APP_NAME} {APP_VERSION}"
        writer.add_metadata(metadata)
    else:
        writer.add_metadata({"/AKaaTHPostprocessor": f"{APP_NAME} {APP_VERSION}"})

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as handle:
        writer.write(handle)


def output_paths(source_path: Path, output_dir: Path | None) -> dict[str, Path]:
    directory = output_dir or source_path.parent
    base = directory / f"{source_path.stem}{SIGNED_SUFFIX}"
    pdf_path = base.with_suffix(".pdf")
    return {
        "pdf": pdf_path,
        "manifest": Path(str(base) + ".provenance.json"),
        "sha256": Path(str(pdf_path) + ".sha256"),
        "sig": Path(str(pdf_path) + ".sig"),
        "verification": Path(str(base) + ".verification.json"),
        "manifest_payload": Path(str(base) + ".manifest.payload"),
        "manifest_request": Path(str(base) + ".manifest-request.json"),
        "artifact_payload": Path(str(base) + ".artifact.payload"),
        "artifact_request": Path(str(base) + ".artifact-request.json"),
    }


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_sha256_sidecar(path: Path, digest: str, filename: str) -> None:
    path.write_text(f"{digest}  {filename}\n", encoding="ascii")


def registries_from_args(args: argparse.Namespace) -> dict[str, str | None]:
    return {
        "validation_schema": getattr(args, "manifest_schema_url", None),
        "engine_registry": getattr(args, "engine_registry_url", None),
        "public_key_registry": getattr(args, "public_key_registry_url", None),
        "provenance_policy": getattr(args, "provenance_policy_url", None),
        "repository": getattr(args, "repository_url", None),
    }


def engine_from_args(args: argparse.Namespace) -> EngineProfile:
    profile_name = getattr(args, "engine_profile", "general")
    base = ENGINE_PROFILES[profile_name]
    return EngineProfile(
        engine_id=getattr(args, "engine_id", None) or base.engine_id,
        name=getattr(args, "engine_name", None) or base.name,
        version=getattr(args, "engine_version", None) or base.version,
        classification=getattr(args, "engine_classification", None) or base.classification,
        function=getattr(args, "engine_function", None) or base.function,
        derived_from=getattr(args, "derived_from", None) or base.derived_from,
    )


def make_core_from_args(source_path: Path, args: argparse.Namespace) -> dict[str, Any]:
    source_bytes = source_path.read_bytes()
    engine = engine_from_args(args)
    operation = getattr(args, "operation", None)
    if not operation:
        operation = {
            "prompt-auditor": "PROMPT_AUDIT",
            "document-structurer": "DOCUMENT_STRUCTURING",
            "general": "DOCUMENT_TRANSFORMATION",
        }[getattr(args, "engine_profile", "general")]

    return build_manifest_core(
        source_path=source_path,
        source_sha256=sha256_bytes(source_bytes),
        source_size=len(source_bytes),
        engine=engine,
        operation_type=operation,
        intervention_scope=["VISIBLE_PROVENANCE_PAGE", "SOURCE_PDF_HASH", "CANONICAL_MANIFEST_HASH"],
        author=getattr(args, "author", DEFAULT_AUTHOR),
        contact=getattr(args, "contact", DEFAULT_CONTACT),
        document_id=getattr(args, "document_id", None) or default_document_id(engine.engine_id),
        execution_id=str(uuid.uuid4()),
        generated_at=now_iso(),
        source_author=getattr(args, "source_author", None),
        session_reference=getattr(args, "session_reference", None),
        registries=registries_from_args(args),
    )


def verify_package(args: argparse.Namespace) -> dict[str, Any]:
    pdf_path = Path(args.pdf).expanduser()
    provenance_path = Path(args.provenance).expanduser() if args.provenance else Path(str(pdf_path.with_suffix("")) + ".provenance.json")
    if not provenance_path.exists():
        provenance_path = pdf_path.with_suffix(".provenance.json")
    if not provenance_path.exists():
        raise AKaaTHError("No se encontro el archivo de procedencia.")

    envelope = json.loads(provenance_path.read_text(encoding="utf-8"))
    manifest = envelope["akaath_provenance_manifest"]
    proof = manifest["cryptographic_proof"]

    core = copy.deepcopy(manifest)
    core.pop("content_integrity", None)
    core.pop("cryptographic_proof", None)
    core_bytes = canonical_json_bytes(core)
    calculated_manifest_digest = sha256_bytes(core_bytes)
    expected_manifest_digest = manifest["content_integrity"]["canonical_manifest_core"]["value"]
    manifest_hash_valid = calculated_manifest_digest == expected_manifest_digest

    pdf_bytes = pdf_path.read_bytes()
    calculated_pdf_digest = sha256_bytes(pdf_bytes)
    expected_pdf_digest = envelope["artifact_integrity"]["value"]
    pdf_hash_valid = calculated_pdf_digest == expected_pdf_digest

    manifest_signature_valid: bool | None = None
    artifact_signature_valid: bool | None = None
    fingerprint_match: bool | None = None

    if args.public_key:
        public_key = load_public_key(Path(args.public_key).expanduser())
        fingerprint = public_key_fingerprint(public_key)
        recorded_fingerprint = proof.get("public_key_fingerprint")
        fingerprint_match = (recorded_fingerprint is None or recorded_fingerprint == fingerprint)

        manifest_signature = proof.get("signature")
        if manifest_signature:
            try:
                public_key.verify(b64url_decode(manifest_signature), core_bytes)
                manifest_signature_valid = True
            except InvalidSignature:
                manifest_signature_valid = False

        artifact_signature = envelope.get("artifact_proof", {}).get("signature")
        if artifact_signature:
            try:
                public_key.verify(b64url_decode(artifact_signature), pdf_bytes)
                artifact_signature_valid = True
            except InvalidSignature:
                artifact_signature_valid = False

    overall = (
        manifest_hash_valid
        and pdf_hash_valid
        and manifest_signature_valid is not False
        and artifact_signature_valid is not False
        and fingerprint_match is not False
    )
    result = {
        "pdf": str(pdf_path),
        "provenance": str(provenance_path),
        "manifest_hash_valid": manifest_hash_valid,
        "pdf_hash_valid": pdf_hash_valid,
        "manifest_signature_valid": manifest_signature_valid,
        "artifact_signature_valid": artifact_signature_valid,
        "public_key_fingerprint_match": fingerprint_match,
        "overall_valid": overall,
    }
    if args.report:
        write_json(Path(args.report).expanduser(), result)
    return result


def add_common_manifest_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--engine-profile", choices=sorted(ENGINE_PROFILES), default="general")
    parser.add_argument("--engine-id")
    parser.add_argument("--engine-name")
    parser.add_argument("--engine-version")
    parser.add_argument("--engine-classification")
    parser.add_argument("--engine-function")
    parser.add_argument("--derived-from")
    parser.add_argument("--operation")
    parser.add_argument("--author", default=DEFAULT_AUTHOR)
    parser.add_argument("--contact", default=DEFAULT_CONTACT)
    parser.add_argument("--source-author")
    parser.add_argument("--document-id")
    parser.add_argument("--session-reference")
    parser.add_argument("--manifest-schema-url")
    parser.add_argument("--engine-registry-url")
    parser.add_argument("--public-key-registry-url")
    parser.add_argument("--provenance-policy-url")
    parser.add_argument("--repository-url", default="https://github.com/alessamiau/akaath-core")


def add_local_signing_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mode", choices=LOCAL_MODES, default="auto")
    parser.add_argument("--private-key")
    parser.add_argument("--key-id", default=DEFAULT_KEY_ID)
    parser.add_argument("--password-env")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="akaath_pdf_signer.py", description="Posprocesa PDFs existentes: agrega firma visible, hashes y firmas Ed25519 opcionales sin sobrescribir el original.")
    parser.add_argument("--version", action="version", version=APP_VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="Generar un par Ed25519.")
    keygen.add_argument("--private-key", required=True)
    keygen.add_argument("--public-key", required=True)
    keygen.add_argument("--key-id", default=DEFAULT_KEY_ID)
    keygen.add_argument("--password-env")
    keygen.add_argument("--unencrypted", action="store_true")
    keygen.add_argument("--overwrite", action="store_true")

    stamp = sub.add_parser("stamp", help="Procesar un PDF local.")
    stamp.add_argument("pdf")
    stamp.add_argument("--output-dir")
    stamp.add_argument("--overwrite", action="store_true")
    add_local_signing_args(stamp)
    add_common_manifest_args(stamp)

    batch = sub.add_parser("batch", help="Procesar todos los PDF de una carpeta.")
    batch.add_argument("--input-dir", required=True)
    batch.add_argument("--output-dir", required=True)
    batch.add_argument("--recursive", action="store_true")
    batch.add_argument("--overwrite", action="store_true")
    add_local_signing_args(batch)
    add_common_manifest_args(batch)

    verify = sub.add_parser("verify", help="Verificar hashes y firmas.")
    verify.add_argument("--pdf", required=True)
    verify.add_argument("--provenance")
    verify.add_argument("--public-key")
    verify.add_argument("--report")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "keygen":
            password = resolve_password(args, confirm=True)
            result = save_keypair(
                Path(args.private_key).expanduser(),
                Path(args.public_key).expanduser(),
                args.key_id,
                password,
                args.overwrite,
            )
        elif args.command == "stamp":
            result = process_one_local(Path(args.pdf).expanduser(), args)
        elif args.command == "batch":
            from pathlib import Path as _P
            input_dir = _P(args.input_dir).expanduser()
            output_dir = _P(args.output_dir).expanduser()
            output_dir.mkdir(parents=True, exist_ok=True)
            results, errors = [], []
            for pdf in sorted(input_dir.glob("*.pdf")):
                if pdf.is_file() and not pdf.stem.endswith(SIGNED_SUFFIX):
                    try:
                        local_args = copy.copy(args)
                        local_args.output_dir = str(output_dir)
                        results.append(process_one_local(pdf, local_args))
                    except Exception as exc:
                        errors.append({"pdf": str(pdf), "error": str(exc)})
            result = {"processed": results, "errors": errors}
        elif args.command == "verify":
            result = verify_package(args)
        else:
            parser.error("Comando no implementado.")
            return 2

        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (AKaaTHError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
