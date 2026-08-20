# Netmiko MCP Server — self-contained. Read-only network device access for Niko (fork de ktbyers/netmiko_mcp).
# By Ed Scrimaglia
#
# ntc-templates is never imported: Netmiko loads it at runtime when a command is
# run with use_textfsm=True. Niko resolves each MCP's dependencies by AST, so the
# package has to be declared here or structured parsing fails inside Niko with an
# error that does not point at the cause. The line below is READ BY THE INSTALLER
# (mcp_dependencies) — it is not a comment to be cleaned up.
#
# mcp-requires: ntc-templates

import asyncio
import base64
import functools
import io
import json
import logging
import logging.handlers
import os
import re
import sys
import threading
import time
import traceback
import uuid
from collections import Counter, deque
from collections.abc import Callable, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version as pkg_version
from pathlib import Path
from typing import Any, Literal, TypeVar

import fastmcp
import requests
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastmcp.server import FastMCP
from netmiko import ConnectHandler
from netmiko.base_connection import BaseConnection
from netmiko.cli_tools.helpers import obtain_devices
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoBaseException,
    NetmikoTimeoutException,
    ReadException,
    ReadTimeout,
    WriteException,
)
from netmiko.ssh_dispatcher import CLASS_MAPPER
from netmiko.utilities import find_cfg_file, load_yaml_file
from paramiko.ssh_exception import SSHException
from pydantic import Field, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

PARENT_DIR = Path(__file__).resolve().parent.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))
load_dotenv(PARENT_DIR / ".env", override=False)

# --- Postura del transporte HTTP -------------------------------------------
#
# Niko elige el transporte, no este archivo: srvclass_general.py:907 arma
# `mcp.run(transport='http', host=..., port=...)` y no pasa ningún flag más, así
# que TODO lo demás queda en los defaults de fastmcp — y los tres relevantes
# vienen en False. El endpoint queda entonces escuchando en 127.0.0.1:8011/mcp
# sin bearer token (invariante: el sondeo de arranque de Niko va sin headers, con
# auth activa daría 401 y Niko concluiría que el server no levantó).
#
# Se fijan acá y NO como campos de McpConfig: test_transport_fields_are_gone
# prohíbe que reaparezcan campos de transporte, porque reabrirían la puerta al
# bearer token. Ninguno de estos tres agrega headers, así que no cae en eso.
#
# host_origin_protection: sin token, la validación de Host/Origin es la única
#   defensa contra DNS rebinding — una página en el browser del operador resuelve
#   su propio dominio a 127.0.0.1 y, siendo same-origin para el browser, llega al
#   endpoint sin CORS de por medio y lee la respuesta. El Host ajeno es el único
#   rastro que deja. En "auto" el guard valida Host porque el bind es loopback
#   (permitidos: 127.0.0.1, localhost, ::1 y el host del bind) y responde 421 al
#   ajeno; el Origin sólo se valida SI el header viene, así que un cliente que no
#   es un browser —el de Niko— no lo nota. El default de fastmcp es False "for
#   compatibility": es un opt-in, no algo que ya estuviera puesto.
# stateless_http: un proceso local con un solo cliente no gana nada guardando
#   estado de sesión, y sí paga que un reinicio del server invalide la sesión.
# json_response: cada tool devuelve un resultado único (la salida grande se
#   pagina en disco), así que el framing SSE no aporta y estorba al diagnosticar.
TRANSPORT_POSTURE: dict[str, object] = {
    "http_host_origin_protection": "auto",
    "stateless_http": True,
    "json_response": True,
}

# Qué se pierde si la versión instalada de fastmcp no define el campo. El aviso
# tiene que nombrar la consecuencia, no el nombre del campo: "no expone X" no le
# dice a un operador si eso lo deja expuesto o si da igual.
TRANSPORT_POSTURE_IF_MISSING: dict[str, str] = {
    "http_host_origin_protection": (
        "el endpoint HTTP no valida Host ni Origin, así que un endpoint sin bearer "
        "token queda sin defensa contra DNS rebinding"
    ),
    "stateless_http": "el transporte HTTP mantiene estado de sesión por cliente",
    "json_response": "las respuestas HTTP salen como stream SSE en vez de JSON",
}

# Los avisos se juntan acá porque `log` todavía no existe: la configuración del
# logging necesita PARENT_DIR y el .env, que se resuelven arriba. Se emiten más
# abajo, con el mismo patrón que log_file_error.
transport_posture_warnings: list[str] = []


def apply_transport_posture() -> None:
    """Fija la postura del transporte tolerando que fastmcp no tenga un campo.

    `fastmcp.settings` valida en la asignación, así que escribir un campo que esa
    versión no define levanta ValidationError. Hecho al importar, eso MATA el
    proceso — y del lado de Niko un proceso muerto al importar se ve idéntico a
    uno que nunca arrancó: `Off` en la UI y nada más. Pasó de verdad: fastmcp
    3.4.2 no tiene `http_host_origin_protection` (3.4.7 sí), y el server no
    levantaba.

    Un campo ausente se saltea con un aviso, nunca con una excepción. El aviso no
    es cosmético: si la protección de Host/Origin no está disponible, el operador
    tiene que saber que ESE endpoint sin bearer token quedó sin defensa contra DNS
    rebinding, en vez de suponerla activa porque el archivo la pide.
    """
    known = set(type(fastmcp.settings).model_fields)
    for name, value in TRANSPORT_POSTURE.items():
        if name not in known:
            transport_posture_warnings.append(
                f"fastmcp {FASTMCP_VERSION} no define '{name}', así que "
                f"{TRANSPORT_POSTURE_IF_MISSING[name]}. Actualizar a fastmcp>=3.4.7."
            )
            continue
        setattr(fastmcp.settings, name, value)


try:
    FASTMCP_VERSION = pkg_version("fastmcp")
except PackageNotFoundError:  # pragma: no cover — depende del entorno
    FASTMCP_VERSION = "desconocida"

apply_transport_posture()


def resolve_project_path(value: str) -> Path:
    """Absolute path for a setting that may arrive relative to the project.

    Un path relativo en el `.mcp.json` se resolvería contra el cwd del proceso
    hijo, que elige el cliente y no el proyecto: Claude Code expande
    `${CLAUDE_PROJECT_DIR:-.}` al default `.` porque esa variable la pone en el
    entorno DEL SERVIDOR, no en el suyo. Anclar en PARENT_DIR — el padre de
    mcps/, la misma raíz de la que sale el .env — hace que el archivo commiteado
    funcione desde cualquier directorio de lanzamiento.

    El `~` sigue ganando: quien escribe `~/commands.yml` quiere su home, no un
    archivo adentro del proyecto.
    """
    path = Path(value).expanduser()
    return path if path.is_absolute() else PARENT_DIR / path

try:
    from niko.srvclass_logging import MCPLogging

    NIKO_AVAILABLE = True
except ImportError:
    MCPLogging = None  # type: ignore[assignment]
    NIKO_AVAILABLE = False

try:
    from niko.niko_paths import NikoPaths
except ImportError:
    NikoPaths = None  # type: ignore[assignment]

if NIKO_AVAILABLE:
    logg_inst = MCPLogging(log_file=os.getenv("LOG_FILE", "Niko.log"))
    log = logg_inst.setup_logging()
else:
    # Fuera de Niko no hay MCPLogging, pero LOG_FILE se declara igual en el
    # .mcp.json: sin este handler la variable no haría nada y los logs sólo
    # existirían mientras el cliente capture stderr. El StreamHandler es a
    # stderr y nunca a stdout — stdout ES el canal JSON-RPC del transporte
    # stdio, y una línea suelta ahí rompe la sesión.
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    log_file_error: str | None = None
    log_file_setting = (os.getenv("LOG_FILE") or "").strip()
    if log_file_setting:
        log_path = resolve_project_path(log_file_setting)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            handlers.append(
                logging.handlers.RotatingFileHandler(
                    log_path, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
                )
            )
            # 0600 igual que el audit trail: en DEBUG este archivo se lleva la
            # salida de los dispositivos, running-configs incluidas.
            log_path.chmod(0o600)
        except OSError as exc:
            log_file_error = (
                f"LOG_FILE '{log_path}' is not writable ({exc}); logging to stderr only"
            )
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s - %(levelname)s - %(funcName)s - %(message)s",
        handlers=handlers,
    )
    log = logging.getLogger("netmiko_mcp")
    if log_file_error:
        log.warning(log_file_error)

# Lo que apply_transport_posture() no pudo fijar, ahora que hay dónde decirlo.
for posture_warning in transport_posture_warnings:
    log.warning(f"Transport: {posture_warning}")

__VERSION__ = "0.1.7"
# Revisión de ktbyers/netmiko_mcp contra la que se diffea la §7 SECURITY. Al
# traer un parche de upstream, esa sección se revisa primero y se mantiene
# literal. Verificado contra 951dfef: el único cambio en security.py desde
# 2c05ff6 es cosmético (comillas de las forward refs de TrieNode), así que §7
# está al día sin parche funcional pendiente.
__UPSTREAM__ = "951dfef"
MCP_NAME = "netmiko"
MCPR_DIR = "mcpr"
FALLBACK_COMMANDS_BY_PLATFORM: dict[str, list[str]] = {
    "cisco_ios / cisco_xe / cisco_nxos / arista_eos": [
        "show version",
        "show inventory",
        "show ip interface brief",
        "show interfaces description",
        "show ip route",
        "show vlan brief",
        "show cdp neighbors",
        "show lldp neighbors",
    ],
    "juniper_junos": [
        "show version",
        "show chassis hardware",
        "show interfaces terse",
        "show route summary",
        "show system uptime",
    ],
    "huawei_vrp / hp_comware": [
        "display version",
        "display device",
        "display ip interface brief",
        "display ip routing-table",
    ],
}

FALLBACK_ALLOWED_COMMANDS = list(
    dict.fromkeys(cmd for cmds in FALLBACK_COMMANDS_BY_PLATFORM.values() for cmd in cmds)
)


def default_audit_log_file() -> str:
    """Ubicación por defecto del audit trail: el directorio de logs de Niko.

    Reusa resolve_log_dir() en vez de leer LOG_PATH a mano porque LOG_PATH es
    relativo en el .env ("./logs") y esa función lo resuelve contra PROJECT_ROOT,
    no contra el cwd del subprocess. Leerlo por nuestra cuenta dejaría el audit
    trail en un directorio distinto al del resto de los logs según desde dónde
    haya arrancado el proceso.

    Fuera de Niko —tests y ejecución standalone— cae al home, que es escribible
    sin privilegios.
    """
    if NIKO_AVAILABLE:
        try:
            return str(MCPLogging.resolve_log_dir() / "netmiko_audit.jsonl")
        except Exception as exc:  # noqa: BLE001 — un helper de Niko ausente o distinto no puede tumbar el arranque  # pragma: no cover — depende del entorno
            log.warning(
                f"Audit: could not resolve Niko's log directory ({exc}); "
                f"the audit trail goes to the home directory."
            )
    return "~/.netmiko_mcp_audit.jsonl"


def resolve_niko_dir(helper_name: str, fallback: Callable[[], Path], label: str) -> Path | None:
    """Path dentro del layout de Niko, o None si no se puede resolver.

    Devuelve None fuera de Niko y también ante cualquier fallo: el llamador
    decide a qué cae. Nunca crea directorios — quién los crea y cuándo es
    justamente lo que distingue config de mcpr, y esa decisión vive en cada
    default, no acá.

    `helper_name` es un helper por MCP de NikoPaths que puede no existir todavía;
    si no está, se usa `fallback`. El probe hace que el día que se agreguen, este
    servidor siga la decisión de layout que traigan, en vez de quedarse con una
    copia que puede divergir en silencio.

    La resolución la hace NikoPaths y no este archivo porque CONFIG_PATH puede
    ser relativo en el .env y `resolve_bootstrap_dir()` lo resuelve contra
    PROJECT_ROOT. Leerlo por nuestra cuenta ataría el path al cwd del subprocess,
    que Niko fija hoy pero es una garantía prestada.
    """
    if NikoPaths is None:
        return None
    try:
        helper = getattr(NikoPaths, helper_name, None)
        return Path(helper(MCP_NAME)) if helper is not None else fallback()
    except Exception as exc:  # noqa: BLE001 — un helper de Niko ausente o distinto no puede tumbar el arranque  # pragma: no cover — depende del entorno
        log.warning(
            f"Could not resolve Niko's '{label}' directory ({exc}); "
            f"falling back to the home directory default."
        )
        return None


def command_file_name(base: Path) -> str:
    """`commands.yml`, or `commands.yaml` when that is the only one present.

    Both extensions because Niko's configuration editor offers both: the
    Configuration → Agent screen lists `**/*.yml` and `**/*.yaml` under
    CONFIG_PATH (`_iter_yaml_files` in nikoapp/backend/config_files.py). A default
    that only looked for `.yml` would let an operator create a file from the UI
    that this server never reads.

    `.yml` wins when both exist: for an allow-list, which of the two is in force
    cannot depend on the order a glob returns them. And when neither exists the
    answer is still `.yml`, so that the `validate_startup()` error names the
    canonical file instead of suggesting the variant.
    """
    if not (base / "commands.yml").is_file() and (base / "commands.yaml").is_file():
        return "commands.yaml"
    return "commands.yml"


def default_command_file() -> str:
    """Allow/deny list: `config/netmiko/commands.yml` dentro de Niko.

    Va en config/ porque es una entrada que escribe el operador, al lado de los
    .json de configuración del propio Niko. Por eso el directorio NO se crea
    solo: si falta, `validate_startup()` corta con un error que lo nombra. Un
    `config/netmiko/` autocreado y vacío daría un servidor que levanta, no
    protesta y deniega todo comando — la falla más cara de diagnosticar.
    """
    base = resolve_niko_dir(
        "mcp_config_dir",
        lambda: Path(NikoPaths.config_dir()) / MCP_NAME,
        "config",
    )
    if base:
        return str(base / command_file_name(base))
    return "~/commands.yml"


def default_save_output_dir() -> str:
    """Salidas grandes: `mcpr/netmiko/` dentro de Niko.

    NO va en output/ — ver el comentario de MCPR_DIR: ese árbol son los
    entregables que sirve el MCP files, y esto es un buffer privado con
    running-configs adentro.

    Al revés que el de config, este directorio sí se crea solo, con modo 0o700,
    la primera vez que se guarda algo (ver `save_device_output()`). Es un
    artefacto que genera el servidor, no una entrada que alguien prepare.
    """
    base = resolve_niko_dir(
        "mcpr_dir",
        lambda: Path(NikoPaths.project_root()) / MCPR_DIR / MCP_NAME,
        "mcpr",
    )
    return str(base) if base else "~/.netmiko_mcp_tmp"


class McpConfig(BaseSettings):
    """Configuración global del servidor MCP de Netmiko.

    Las variables de entorno (prefijo NETMIKO_MCP_) tienen precedencia sobre el
    archivo YAML. Dentro de Niko, la fuente de verdad es el bloque `env` de
    mcps/mcp_config.json, que build_mcp_process_env aplica DESPUÉS de cargar el
    .env — si una variable está en ambos lugares, gana el JSON en silencio.
    Definir cada variable en un solo lugar.
    """

    model_config = SettingsConfigDict(
        env_prefix="NETMIKO_MCP_",
        extra="ignore",
    )

    inventory_type: Literal["netmiko_tools", "yaml", "fedele"] = Field(default="netmiko_tools")
    inventory_file: str | None = Field(default=None)

    credential_source: Literal["env", "fedele"] = Field(default="env")

    fedele_group_source: Literal["tags", "device_roles", "sites"] = Field(default="tags")
    fedele_device_filter: str | None = Field(default=None)
    fedele_cache_ttl: int = Field(default=60)

    command_file: str = Field(default_factory=default_command_file)
    allow_pipe: bool = Field(default=False)
    allowed_command_chars: str = Field(
        default='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ./:_-,"'
    )
    pipe_modifiers: list[str] = Field(default=["include", "exclude", "section", "begin", "count"])

    ssh_config_file: str | None = Field(default=None)

    max_workers: int = Field(default=10)
    save_output_dir: str = Field(default_factory=default_save_output_dir)
    save_threshold: int = Field(default=1000)

    audit_log_enabled: bool = Field(default=True)
    audit_log_destination: Literal["file", "syslog", "both"] = Field(default="file")
    audit_log_file: str = Field(default_factory=default_audit_log_file)
    audit_log_syslog_address: str = Field(default="/dev/log")
    audit_log_syslog_facility: str = Field(default="local0")
    audit_log_read_transcript: bool = Field(default=False)
    audit_log_transcript_dir: str = Field(default="~/.netmiko_mcp_transcripts")

    @property
    def inventory_backend(self) -> str:
        """Backend efectivo: 'fedele' o 'yaml'."""
        return "fedele" if self.inventory_type == "fedele" else "yaml"

    @model_validator(mode="after")
    def check_pipe_char_consistency(self) -> "McpConfig":
        """Rechaza '|' en allowed_command_chars mientras allow_pipe sea False.

        El pipe se gestiona automáticamente vía allow_pipe y no debe agregarse a
        mano al conjunto de caracteres.
        """
        if "|" in self.allowed_command_chars and not self.allow_pipe:
            raise ValueError(
                "'|' must not appear in allowed_command_chars when allow_pipe is False. "
                "Set allow_pipe: true to enable pipe support."
            )
        return self

    @model_validator(mode="after")
    def anchor_relative_paths(self) -> "McpConfig":
        """Los paths relativos quedan anclados a la raíz del proyecto.

        Mismo motivo que `resolve_project_path`: estos valores vienen de un
        .mcp.json commiteado que no puede saber dónde vive el proyecto, así que
        se escriben relativos y el cwd lo decide el cliente. Resolverlos acá una
        sola vez, al cargar, deja intactos los call sites (siguen haciendo
        `Path(...).expanduser()`, que sobre un absoluto es un no-op) y hace que
        los errores de `validate_startup()` nombren el archivo real en disco.
        """
        for field in (
            "inventory_file",
            "command_file",
            "ssh_config_file",
            "save_output_dir",
            "audit_log_file",
            "audit_log_transcript_dir",
        ):
            value = getattr(self, field)
            if value:
                setattr(self, field, str(resolve_project_path(value)))
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Orden de precedencia: init > entorno > YAML.

        Las variables NETMIKO_MCP_* siempre ganan sobre el archivo de config.
        No se soporta .env como fuente de settings (sí como fuente de
        credenciales, que se leen aparte en la sección 5).
        """
        config_path_str = os.environ.get("NETMIKO_MCP_CONFIG")
        if config_path_str:
            config_path = Path(config_path_str).expanduser()
        else:
            config_path = Path.home() / ".netmiko-mcp.yml"

        yaml_source = None
        if config_path.is_file():
            yaml_source = YamlConfigSettingsSource(settings_cls, yaml_file=config_path)

        sources = [init_settings, env_settings]
        if yaml_source:
            sources.append(yaml_source)

        return tuple(sources)


settings = McpConfig()


ALLOWED = "ALLOWED"
DENIED = "DENIED"

REASON_UNSAFE_CHAR = "UNSAFE_CHAR"
REASON_DENY_MATCH = "DENY_MATCH"
REASON_MULTIPLE_PIPES = "MULTIPLE_PIPES"
REASON_INVALID_PIPE_MODIFIER = "INVALID_PIPE_MODIFIER"
REASON_NO_ALLOW_MATCH = "NO_ALLOW_MATCH"
REASON_ALLOWED = "ALLOWED"

OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_AUTH_FAILURE = "AUTH_FAILURE"
OUTCOME_TIMEOUT = "TIMEOUT"
OUTCOME_SSH_ERROR = "SSH_ERROR"
OUTCOME_NETMIKO_ERROR = "NETMIKO_ERROR"
OUTCOME_READ_TIMEOUT = "READ_TIMEOUT"
OUTCOME_READ_ERROR = "READ_ERROR"
OUTCOME_WRITE_ERROR = "WRITE_ERROR"
OUTCOME_ERROR = "ERROR"
OUTCOME_INVENTORY_ERROR = "INVENTORY_ERROR"
OUTCOME_CREDENTIAL_ERROR = "CREDENTIAL_ERROR"
OUTCOME_SOT_ERROR = "SOT_ERROR"

audit_logger = logging.getLogger("netmiko_mcp.audit")

audit_logger.addHandler(logging.NullHandler())

LOGRECORD_BUILTIN_ATTRS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


class AuditJsonFormatter(logging.Formatter):
    """Formatea cada registro como un objeto JSON de una sola línea.

    El timestamp va en ISO 8601 UTC. Todos los campos extra adjuntados vía el
    parámetro extra= del logging se incluyen junto a timestamp y level.
    """

    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
        }
        for key, value in record.__dict__.items():
            if key not in LOGRECORD_BUILTIN_ATTRS:
                data[key] = value
        return json.dumps(data, default=str)


class FailClosedFileHandler(logging.FileHandler):
    """FileHandler que relanza los errores de escritura en vez de tragárselos.

    El comportamiento por defecto de logging captura las excepciones de emit() y
    las deriva a handleError(), que imprime a stderr. Para auditoría eso no
    alcanza: una escritura fallida tiene que propagarse para que el llamador
    falle cerrado. La rotación queda a cargo del operador (logrotate).
    """

    def handleError(self, record: logging.LogRecord) -> None:
        exc_value = sys.exc_info()[1]
        raise RuntimeError(f"Audit log file write failed: {exc_value}") from exc_value


class FailClosedSysLogHandler(logging.handlers.SysLogHandler):
    """SysLogHandler que relanza los errores de escritura."""

    def handleError(self, record: logging.LogRecord) -> None:
        exc_value = sys.exc_info()[1]
        raise RuntimeError(f"Audit syslog write failed: {exc_value}") from exc_value


def build_file_handler(formatter: logging.Formatter) -> logging.Handler:
    """Construye el handler de archivo fail-closed para el audit trail.

    Dentro de Niko usa el handler concurrente de srvclass_logging (rotación
    segura entre procesos) pero con backupCount=0: la retención la decide el
    operador, no un backupCount de 7 días que borraría el rastro a la semana.
    Fuera de Niko cae a logging.FileHandler. En ambos casos handleError relanza.
    """
    log_path = Path(settings.audit_log_file).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handler: logging.Handler | None = None
    if NIKO_AVAILABLE:
        try:
            from niko.srvclass_logging import SyncedConcurrentTimedRotatingFileHandler

            class NikoAuditHandler(SyncedConcurrentTimedRotatingFileHandler):  # type: ignore[misc]
                def handleError(self, record: logging.LogRecord) -> None:
                    exc_value = sys.exc_info()[1]
                    raise RuntimeError(f"Audit log write failed: {exc_value}") from exc_value

            handler = NikoAuditHandler(
                filename=str(log_path),
                when="midnight",
                backupCount=0,
                force_sync=True,
                encoding="utf-8",
            )
        except Exception as exc:  # noqa: BLE001 — si el handler de Niko no sirve, se cae al de la stdlib  # pragma: no cover — depende del entorno
            log.warning(
                f"Audit: could not use Niko's concurrent handler ({exc}); "
                f"falling back to FileHandler."
            )
            handler = None

    if handler is None:
        handler = FailClosedFileHandler(filename=str(log_path), mode="a", encoding="utf-8")

    if log_path.exists():
        log_path.chmod(0o600)
    handler.setFormatter(formatter)
    return handler


def build_syslog_handler(formatter: logging.Formatter) -> FailClosedSysLogHandler:
    """Construye el handler de syslog fail-closed.

    audit_log_syslog_address puede ser un socket UNIX ('/dev/log') o 'host:port'
    para syslog UDP remoto. La facility se resuelve por nombre desde
    audit_log_syslog_facility y cae a local0.
    """
    address_str = settings.audit_log_syslog_address
    address: str | tuple[str, int]
    if ":" in address_str and not address_str.startswith("/"):
        host, port_str = address_str.rsplit(":", 1)
        address = (host, int(port_str))
    else:
        address = address_str

    facility = logging.handlers.SysLogHandler.facility_names.get(
        settings.audit_log_syslog_facility,
        logging.handlers.SysLogHandler.LOG_LOCAL0,
    )
    handler = FailClosedSysLogHandler(address=address, facility=facility)  # type: ignore[arg-type]
    handler.setFormatter(formatter)
    return handler


def configure_audit_logger() -> None:
    """Configura el logger de auditoría según la configuración vigente.

    Se llama una vez al arrancar, antes de cualquier invocación de tool. Con
    audit_log_enabled en False es un no-op: el NullHandler agregado al importar
    mantiene el logger callado sin warnings.
    """
    if not settings.audit_log_enabled:
        return

    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

    formatter = AuditJsonFormatter()
    destination = settings.audit_log_destination

    if destination in ("file", "both"):
        audit_logger.addHandler(build_file_handler(formatter))
    if destination in ("syslog", "both"):
        audit_logger.addHandler(build_syslog_handler(formatter))


def emit_audit_record(fields: dict[str, Any]) -> None:
    """Emite un registro estructurado de auditoría.

    Los campos van como atributos extra del LogRecord y los serializa
    AuditJsonFormatter. Con audit_log_enabled en False no hace nada. Si un
    handler lanza (porque handleError relanza), la excepción se propaga al
    llamador: eso es la política fail-closed.
    """
    if not settings.audit_log_enabled:
        return
    audit_logger.info("audit", extra=fields)


def log_command_attempt(
    *,
    correlation_id: str,
    tool: str,
    device: str,
    command: str,
    verdict: str,
    reason: str,
) -> None:
    """Registro de auditoría de un intento de validación de comando.

    Se llama inmediatamente después de validate_command(), haya sido permitido o
    denegado. reason es una de las constantes REASON_*.
    """
    if verdict == ALLOWED:
        log.debug(
            f"Command allowed on '{device}': command='{command}' "
            f"tool='{tool}' correlation_id={correlation_id}"
        )
    else:
        log.info(
            f"Command denied on '{device}': command='{command}' reason={reason} "
            f"tool='{tool}' correlation_id={correlation_id}"
        )
    emit_audit_record(
        {
            "event": "command_attempt",
            "correlation_id": correlation_id,
            "tool": tool,
            "device": device,
            "command": command,
            "verdict": verdict,
            "reason": reason,
            "policy_source": command_policy_source(),
        }
    )


def log_connection_outcome(
    *,
    correlation_id: str,
    tool: str,
    device: str,
    command: str,
    outcome: str,
    detail: str | None = None,
    textfsm_parse_failed: bool = False,
) -> None:
    """Registro de auditoría del resultado de la conexión y ejecución.

    Se llama cuando termina el intento SSH, con éxito o sin él. outcome es una
    de las constantes OUTCOME_*. detail lleva el mensaje de excepción en las
    fallas. textfsm_parse_failed se marca cuando se pidió use_textfsm=True pero
    el parseo cayó a texto plano.
    """
    if outcome == OUTCOME_SUCCESS:
        log.debug(
            f"Command completed on '{device}': tool='{tool}' "
            f"correlation_id={correlation_id}"
            + (" textfsm_parse_failed=True" if textfsm_parse_failed else "")
        )
    else:
        log.warning(
            f"Command failed on '{device}': outcome={outcome} command='{command}' "
            f"tool='{tool}' correlation_id={correlation_id}"
            + (f" detail='{detail}'" if detail else "")
        )
    fields: dict[str, Any] = {
        "event": "connection_outcome",
        "correlation_id": correlation_id,
        "tool": tool,
        "device": device,
        "command": command,
        "outcome": outcome,
    }
    if detail is not None:
        fields["detail"] = detail
    if textfsm_parse_failed:
        fields["textfsm_parse_failed"] = True
    emit_audit_record(fields)


def log_tool_invocation(*, tool: str, arguments: dict[str, Any]) -> None:
    """Registro de auditoría de una tool que no ejecuta comandos en dispositivos.

    Cubre health_check, list_devices, list_groups, list_device_outputs y
    read_device_output, para que toda operación MCP quede rendida.
    """
    emit_audit_record(
        {
            "event": "tool_invocation",
            "tool": tool,
            "arguments": arguments,
        }
    )


def log_credential_resolution(*, device: str, source: str, credential_ref: str) -> None:
    """Registro de auditoría de qué credencial se usó para un dispositivo.

    credential_ref identifica el objeto de credencial (id o nombre), NUNCA su
    valor. Es lo que permite reconstruir con qué cuenta se tocó cada equipo sin
    que el secreto quede escrito en ningún lado.
    """
    log.debug(
        f"Credential resolved for '{device}': source={source} "
        f"credential_ref='{credential_ref}'"
    )
    emit_audit_record(
        {
            "event": "credential_resolution",
            "device": device,
            "source": source,
            "credential_ref": credential_ref,
        }
    )


def save_channel_transcript(
    correlation_id: str,
    device_name: str,
    raw_bytes: bytes,
) -> None:
    """Guarda el transcript del canal SSH en un archivo por conexión.

    Los archivos se nombran por timestamp, correlation ID y dispositivo para
    poder cruzarlos con los registros de auditoría durante una investigación. El
    directorio no se limpia solo: la rotación y el espacio en disco son
    responsabilidad del operador.

    Solo debe llamarse con audit_log_read_transcript en True; el llamador es
    quien verifica la configuración antes de crear el buffer.

    Como el eco de terminal SSH hace que el equipo devuelva los comandos
    enviados por el canal de lectura, el transcript captura lo enviado sin
    necesidad de interceptar el lado de escritura.
    """
    transcript_dir = Path(settings.audit_log_transcript_dir).expanduser()
    transcript_dir.mkdir(parents=True, exist_ok=True)
    transcript_dir.chmod(0o700)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    safe_device = "".join(c if c.isalnum() or c in "-_." else "_" for c in device_name)
    filename = f"{timestamp}_{correlation_id}_{safe_device}.txt"
    file_path = transcript_dir / filename

    transcript_text = raw_bytes.decode("utf-8", errors="replace")

    file_path.write_text(transcript_text, encoding="utf-8")
    file_path.chmod(0o600)


AUDIT_DESTINATION_SYSLOG = "syslog"

# Derivadas de las constantes de arriba a propósito: una lista escrita a mano se
# desincroniza en silencio la primera vez que alguien agrega un OUTCOME_*, y el
# filtro rechazaría un valor que el audit sí escribe.
AUDIT_REASONS: tuple[str, ...] = (
    REASON_UNSAFE_CHAR,
    REASON_DENY_MATCH,
    REASON_MULTIPLE_PIPES,
    REASON_INVALID_PIPE_MODIFIER,
    REASON_NO_ALLOW_MATCH,
    REASON_ALLOWED,
)

AUDIT_OUTCOMES: tuple[str, ...] = (
    OUTCOME_SUCCESS,
    OUTCOME_AUTH_FAILURE,
    OUTCOME_TIMEOUT,
    OUTCOME_SSH_ERROR,
    OUTCOME_NETMIKO_ERROR,
    OUTCOME_READ_TIMEOUT,
    OUTCOME_READ_ERROR,
    OUTCOME_WRITE_ERROR,
    OUTCOME_ERROR,
    OUTCOME_INVENTORY_ERROR,
    OUTCOME_CREDENTIAL_ERROR,
    OUTCOME_SOT_ERROR,
)

AUDIT_EVENTS = (
    "command_attempt",
    "connection_outcome",
    "tool_invocation",
    "credential_resolution",
)

AUDIT_SUMMARY_KEYS = ("device", "tool", "outcome", "verdict", "event", "day")

AUDIT_QUERY_TOOL_NAME = "netmiko.query_audit_trail"

AUDIT_QUERY_MAX_LIMIT = 500


class AuditQueryError(Exception):
    """An audit query cannot be answered as asked.

    Raised for an argument the caller got wrong, never for a record that simply
    does not match. The distinction matters: a bad filter that returned an empty
    list would read as "nothing happened", which is the one answer an audit trail
    must never give by accident.
    """


def parse_audit_time(value: str, field: str) -> datetime:
    """Parse an ISO 8601 timestamp from a tool argument, as aware UTC.

    A bare date ('2026-08-17') means midnight UTC, which is what someone asking
    "since the 17th" means. A naive datetime is read as UTC rather than local
    time: every audit timestamp is written in UTC, so interpreting the query in
    the server's timezone would silently shift the window.
    """
    raw = value.strip()
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise AuditQueryError(
            f"{field}='{value}' is not an ISO 8601 date or datetime "
            f"(expected '2026-08-17' or '2026-08-17T14:30:00Z')."
        ) from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def audit_file_day(path: Path, current_name: str) -> str | None:
    """The UTC day a rotated audit file holds, from its filename suffix.

    TimedRotatingFileHandler names yesterday's file 'netmiko_audit.jsonl.2026-08-17'.
    Returns None for the file currently being written, which holds today and has
    no suffix, and for any suffix that is not a date — a stray file next to the
    audit trail is skipped rather than guessed at.
    """
    if path.name == current_name:
        return None
    suffix = path.name[len(current_name):].lstrip(".")
    try:
        datetime.strptime(suffix, "%Y-%m-%d")  # noqa: DTZ007 — sólo valida que el sufijo sea una fecha; el datetime se descarta
    except ValueError:
        return None
    return suffix


def audit_files(since: datetime | None = None) -> list[Path]:
    """Audit files to scan in chronological order: rotated days first, live file last.

    The order is not cosmetic. read_audit_records() keeps the tail of what it sees
    in a bounded deque, so "the newest N records" is only the newest N if the
    files are read oldest-first. Reading the live file first made a desc query
    return the OLDEST page, which looked like a plausible answer and was wrong.

    Rotation is daily. Inside Niko the handler is a TimedRotatingFileHandler with
    backupCount=0, so every rotated day is kept and a query that only read the
    live file would cover from midnight — useless for "what happened last week".
    Standalone there is no rotation at all (FailClosedFileHandler; the operator
    rotates with logrotate), so the list is usually one file.

    Two guards, both deliberate:

    - Every candidate must resolve inside the audit directory, the same check
      read_saved_output() makes. Nothing here comes from the caller, but the
      directory is operator-configured and may hold symlinks.
    - When `since` is given, a rotated file whose day is entirely older is
      dropped without being opened. That is what keeps a query bounded when
      months of audit have accumulated.
    """
    audit_path = Path(settings.audit_log_file).expanduser()
    directory = audit_path.parent
    if not directory.is_dir():
        return []

    try:
        base = directory.resolve()
    except OSError:  # pragma: no cover — depende del entorno
        return []

    since_day = since.strftime("%Y-%m-%d") if since else None
    selected: list[tuple[str, Path]] = []
    for candidate in directory.glob(f"{audit_path.name}*"):
        if not candidate.is_file():
            continue
        try:
            if not candidate.resolve().is_relative_to(base):
                log.warning(
                    f"Audit query: skipping '{candidate.name}' — it resolves outside "
                    f"the audit directory."
                )
                continue
        except OSError:  # pragma: no cover — depende del entorno
            continue
        day = audit_file_day(candidate, audit_path.name)
        if day is None and candidate.name != audit_path.name:
            continue
        if since_day and day is not None and day < since_day:
            continue
        # The live file has no date suffix and holds today, so it gets a sentinel
        # that sorts after every rotated day.
        selected.append((day or "9999-99-99", candidate))

    return [entry[1] for entry in sorted(selected)]


def audit_record_matches(record: dict[str, Any], filters: dict[str, str]) -> bool:
    """Whether one audit record satisfies every active filter (AND).

    `command_contains` is a case-insensitive substring; everything else is an
    exact match on the field. A filter naming a field the record does not carry
    excludes it — a tool_invocation has no 'verdict', so asking for DENIED must
    not return it.
    """
    for field, wanted in filters.items():
        if field == "command_contains":
            if wanted.lower() not in str(record.get("command", "")).lower():
                return False
        elif str(record.get(field, "")) != wanted:
            return False
    return True


def read_audit_records(
    *,
    filters: dict[str, str],
    since: datetime | None,
    until: datetime | None,
    order: str,
    limit: int,
    summary_key: str = "",
    exclude_tool: str = "",
) -> dict[str, Any]:
    """Stream the audit trail and return the matching records plus what was scanned.

    Blocking I/O: call it through asyncio.to_thread.

    With `summary_key` set this counts into a Counter as it goes and keeps no
    records at all, so a summary is exact over the whole trail instead of over
    the first page — "how many commands were refused this week" has to be a real
    total, and it costs no memory to make it one.

    Memory stays bounded in the listing path too: for order='desc' the newest
    `limit` matches are kept in a deque, so a query over a large trail never
    holds more than one page plus one line.

    `exclude_tool` drops the records one tool wrote before anything else looks at
    them, so they count towards neither `matched` nor the summary.

    A line that is not valid JSON, or is JSON but not an object, is counted in
    `malformed_lines` and skipped. Aborting would let one corrupt line — a
    half-written record from a killed process — hide the entire history.
    """
    files = audit_files(since)
    matched = 0
    malformed = 0
    oldest: str | None = None
    kept: deque[dict[str, Any]] = deque(maxlen=limit if order == "desc" else None)
    counter: Counter[str] = Counter()
    excluded = 0

    for path in files:
        try:
            handle = path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            raise AuditQueryError(f"audit file '{path.name}' could not be read: {exc}") from exc
        with handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    malformed += 1
                    continue
                if not isinstance(record, dict):
                    malformed += 1
                    continue

                if exclude_tool and record.get("tool") == exclude_tool:
                    excluded += 1
                    continue

                stamp = record.get("timestamp")
                if isinstance(stamp, str) and (oldest is None or stamp < oldest):
                    oldest = stamp
                if since or until:
                    try:
                        when = datetime.fromisoformat(str(stamp))
                    except ValueError:
                        malformed += 1
                        continue
                    if when.tzinfo is None:
                        when = when.replace(tzinfo=UTC)
                    if since and when < since:
                        continue
                    if until and when > until:
                        continue

                if not audit_record_matches(record, filters):
                    continue

                matched += 1
                if summary_key:
                    counter[audit_group_value(record, summary_key)] += 1
                    continue
                if order == "desc":  # noqa: SIM114 — las ramas dicen cosas distintas: en desc se guarda todo y se recorta después
                    kept.append(record)
                elif len(kept) < limit:
                    kept.append(record)

    records = list(kept)
    if order == "desc":
        records.reverse()
    return {
        "records": records,
        "summary": dict(counter.most_common()),
        "matched": matched,
        "excluded": excluded,
        "malformed_lines": malformed,
        "files_scanned": [path.name for path in files],
        "oldest_available": oldest,
    }


def audit_group_value(record: dict[str, Any], key: str) -> str:
    """The bucket one record falls into when summarizing by `key`.

    'day' buckets by the UTC date of the timestamp. A record that does not carry
    the field goes to '(absent)' instead of being dropped: a summary by device
    that silently ignored the tool_invocation records would under-report the very
    activity it claims to total, and the counts would not add up to `matched`.
    """
    if key == "day":
        return str(record.get("timestamp", ""))[:10] or "(absent)"
    return str(record.get(key, "")) or "(absent)"


def validate_audit_choice(value: str, field: str, allowed: tuple[str, ...]) -> str:
    """Return a stripped enumerated argument, or raise naming the valid options.

    Rejecting is the point. Ignoring an unrecognised filter would return records
    that look filtered and are not, and the caller would report that as fact.
    """
    cleaned = value.strip()
    if not cleaned:
        return ""
    if cleaned not in allowed:
        raise AuditQueryError(
            f"{field}='{value}' is not valid. Options: {', '.join(allowed)}."
        )
    return cleaned


def run_audit_query(
    *,
    event: str,
    device: str,
    tool: str,
    command_contains: str,
    verdict: str,
    reason: str,
    outcome: str,
    correlation_id: str,
    since: str,
    until: str,
    order: str,
    limit: int,
    summary_by: str,
    include_audit_queries: bool,
) -> dict[str, Any]:
    """Validate the query arguments, run it, and shape the response payload.

    Blocking: called through asyncio.to_thread by the tool. Kept separate from the
    tool so the whole query surface is testable without going through FastMCP.
    """
    filters: dict[str, str] = {}
    if e := validate_audit_choice(event, "event", AUDIT_EVENTS):
        filters["event"] = e
    if v := validate_audit_choice(verdict, "verdict", (ALLOWED, DENIED)):
        filters["verdict"] = v
    if r := validate_audit_choice(reason, "reason", AUDIT_REASONS):
        filters["reason"] = r
    if o := validate_audit_choice(outcome, "outcome", AUDIT_OUTCOMES):
        filters["outcome"] = o
    for field, value in (
        ("device", device),
        ("tool", tool),
        ("correlation_id", correlation_id),
        ("command_contains", command_contains),
    ):
        if value.strip():
            filters[field] = value.strip()

    order_clean = order.strip().lower() or "desc"
    if order_clean not in ("asc", "desc"):
        raise AuditQueryError(f"order='{order}' is not valid. Options: asc, desc.")

    summary_key = validate_audit_choice(summary_by, "summary_by", AUDIT_SUMMARY_KEYS)

    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise AuditQueryError(f"limit='{limit}' must be a positive integer.")
    capped_limit = min(limit, AUDIT_QUERY_MAX_LIMIT)

    since_dt = parse_audit_time(since, "since") if since.strip() else None
    until_dt = parse_audit_time(until, "until") if until.strip() else None
    if since_dt and until_dt and since_dt > until_dt:
        raise AuditQueryError(
            f"since='{since}' is later than until='{until}', so the window is empty."
        )

    # Querying the audit writes a tool_invocation of its own, so a few questions in
    # "the last 6 actions" would be six audit queries. The record stays — who read
    # the trail is part of the trail — but it is out of the answer unless the
    # caller asks for it, or filters for it on purpose.
    asked_for_self = filters.get("tool") == AUDIT_QUERY_TOOL_NAME
    exclude_tool = "" if (include_audit_queries or asked_for_self) else AUDIT_QUERY_TOOL_NAME

    result = read_audit_records(
        filters=filters,
        since=since_dt,
        until=until_dt,
        order=order_clean,
        limit=capped_limit,
        summary_key=summary_key,
        exclude_tool=exclude_tool,
    )

    payload: dict[str, Any] = {
        "success": True,
        "matched": result["matched"],
        "files_scanned": result["files_scanned"],
        "oldest_available": result["oldest_available"],
        "malformed_lines": result["malformed_lines"],
        "filters_applied": filters or None,
    }
    if result["excluded"]:
        payload["audit_queries_hidden"] = result["excluded"]
    if since_dt:
        payload["since"] = since_dt.isoformat()
    if until_dt:
        payload["until"] = until_dt.isoformat()

    if summary_key:
        # The counts are exact over every matching record, so there is no page to
        # truncate and nothing for the caller to add up itself.
        payload["summary_by"] = summary_key
        payload["summary"] = result["summary"]
        payload["truncated"] = False
    else:
        payload["records"] = result["records"]
        payload["returned"] = len(result["records"])
        payload["order"] = order_clean
        payload["limit"] = capped_limit
        payload["truncated"] = result["matched"] > len(result["records"])

    if not result["files_scanned"]:
        payload["note"] = (
            f"No audit file was found at '{settings.audit_log_file}'. Nothing has been "
            f"recorded yet, or the path is not the one the server writes to."
        )
    return payload


@dataclass
class CommandAuditContext:
    """Argumentos invariantes compartidos por todos los registros de auditoría
    de una misma invocación de run_show_command.

    Se construye una vez por llamada y se usa en todo el cuerpo, evitando repetir
    los cuatro keyword arguments en cada log_command_attempt y
    log_connection_outcome.
    """

    correlation_id: str
    tool: str
    device: str
    command: str

    def log_attempt(self, verdict: str, reason: str) -> None:
        """Emite el registro command_attempt de esta invocación."""
        log_command_attempt(
            correlation_id=self.correlation_id,
            tool=self.tool,
            device=self.device,
            command=self.command,
            verdict=verdict,
            reason=reason,
        )

    def log_outcome(
        self,
        outcome: str,
        detail: str | None = None,
        textfsm_parse_failed: bool = False,
    ) -> None:
        """Emite el registro connection_outcome de esta invocación."""
        log_connection_outcome(
            correlation_id=self.correlation_id,
            tool=self.tool,
            device=self.device,
            command=self.command,
            outcome=outcome,
            detail=detail,
            textfsm_parse_failed=textfsm_parse_failed,
        )


class FedeleError(Exception):
    """Base de los errores de acceso a Fedele."""


class FedeleConfigError(FedeleError):
    """Falta configuración, o el token no autoriza.

    Se distingue de FedeleUnavailable a propósito: esto no se arregla esperando,
    así que no abre el circuit breaker. Reintentar en 30 segundos daría el mismo
    401.
    """


class FedeleUnavailable(FedeleError):
    """Fedele no responde: red, DNS, TLS, timeout o error del servidor."""


class TTLCache:
    """Caché en memoria con vencimiento por tiempo.

    Los datos de conexión y las credenciales se cachean con TTL corto, no con
    lru_cache: contra una fuente dinámica, un caché sin vencimiento devuelve
    direcciones y credenciales viejas indefinidamente, que es peor que pagar el
    round-trip REST.
    """

    def __init__(self, ttl_seconds: int) -> None:
        self.ttl = max(0, ttl_seconds)
        self.data: dict[Any, tuple[float, Any]] = {}
        self.lock = threading.Lock()

    def get(self, key: Any) -> Any | None:
        if self.ttl <= 0:
            return None
        with self.lock:
            entry = self.data.get(key)
            if entry is None:
                return None
            stored_at, value = entry
            if time.monotonic() - stored_at > self.ttl:
                self.data.pop(key, None)
                return None
            return value

    def set(self, key: Any, value: Any) -> None:
        if self.ttl > 0:
            with self.lock:
                self.data[key] = (time.monotonic(), value)

    def clear(self) -> None:
        with self.lock:
            self.data.clear()


class FedeleClient:
    """Cliente REST de solo lectura contra Fedele, con circuit breaker.

    Tras una falla de transporte o un 5xx, corta en seco los pedidos siguientes
    durante UNAVAILABLE_WINDOW segundos en vez de reintentar. Importa porque los
    comandos de grupo resuelven inventario y credenciales de N equipos en
    paralelo: sin el corte, un Fedele caído cuesta N timeouts completos.

    El estado del breaker se comparte entre hilos, así que va bajo lock: el
    ThreadPoolExecutor de run_show_command_on_group llega acá desde varios hilos
    a la vez.
    """

    UNAVAILABLE_WINDOW = 30
    TIMEOUT = 20

    def __init__(self) -> None:
        base = (os.getenv("FEDELE_URL") or "").strip().rstrip("/")
        if not base:
            raise FedeleConfigError("FEDELE_URL is not set in the environment.")
        self.api_url = base if base.endswith("/api") else f"{base}/api"
        self.token = (os.getenv("FEDELE_TOKEN") or "").strip()
        if not self.token:
            raise FedeleConfigError("FEDELE_TOKEN is not set in the environment.")
        self.verify_ssl = (
            os.getenv("FEDELE_VERIFY_SSL", "true").lower() not in ("false", "0", "no")
        )
        self.session: Any = None
        self.session_lock = threading.Lock()
        self.breaker_lock = threading.Lock()
        self.unavailable_until = 0.0
        self.unavailable_reason = ""


    def trip_breaker(self, reason: str) -> None:
        """Abre el breaker por UNAVAILABLE_WINDOW segundos."""
        with self.breaker_lock:
            self.unavailable_until = time.monotonic() + self.UNAVAILABLE_WINDOW
            self.unavailable_reason = reason
        log.warning(
            f"Fedele: circuit breaker opened for {self.UNAVAILABLE_WINDOW}s — {reason}"
        )

    def reset_breaker(self) -> None:
        """Cierra el breaker tras un pedido exitoso."""
        with self.breaker_lock:
            if self.unavailable_until:
                log.info("Fedele: responding again, circuit breaker closed.")
            self.unavailable_until = 0.0
            self.unavailable_reason = ""

    def breaker_is_open(self) -> str | None:
        """Motivo y tiempo restante si el breaker está abierto; None si no."""
        with self.breaker_lock:
            if not self.unavailable_until:
                return None
            remaining = self.unavailable_until - time.monotonic()
            if remaining <= 0:
                self.unavailable_until = 0.0
                self.unavailable_reason = ""
                return None
            return f"{self.unavailable_reason} (reintentar en {remaining:.0f}s)"

    @property
    def available(self) -> bool:
        """False mientras el breaker esté abierto. Para netmiko.get_metadata."""
        return self.breaker_is_open() is None


    def get_session(self) -> Any:
        if self.session is None:
            with self.session_lock:
                if self.session is None:
                    session = requests.Session()
                    session.headers.update(
                        {
                            "Authorization": f"Token {self.token}",
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                        }
                    )
                    self.session = session
        return self.session

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET contra Fedele. Devuelve el JSON crudo, sin desenvolver.

        Distingue tres familias de falla, porque piden acciones distintas:
          - FedeleUnavailable  → transporte o 5xx. Abre el breaker.
          - FedeleConfigError  → 401/403. No abre el breaker: no se cura solo.
          - FedeleError        → cualquier otro no-200.
        """
        blocked = self.breaker_is_open()
        if blocked:
            raise FedeleUnavailable(f"Fedele no disponible: {blocked}")

        url = f"{self.api_url}/{path.lstrip('/')}"
        started = time.monotonic()
        try:
            response = self.get_session().get(
                url, params=params or {}, verify=self.verify_ssl, timeout=self.TIMEOUT
            )
        except requests.exceptions.RequestException as exc:
            reason = f"{type(exc).__name__} against {self.api_url}"
            log.warning(
                f"Fedele did not respond on '{path}' after "
                f"{time.monotonic() - started:.1f}s: error={type(exc).__name__} — "
                f"opening the circuit breaker"
            )
            self.trip_breaker(reason)
            raise FedeleUnavailable(
                f"Fedele is not responding at {self.api_url}: {exc}"
            ) from exc

        elapsed = time.monotonic() - started
        log.debug(
            f"Fedele GET '{path}' params={params or {}} -> HTTP {response.status_code} "
            f"in {elapsed:.2f}s"
        )

        if response.status_code >= 500:
            reason = f"HTTP {response.status_code} on {path}"
            log.warning(
                f"Fedele returned HTTP {response.status_code} on '{path}' — "
                f"opening the circuit breaker"
            )
            self.trip_breaker(reason)
            raise FedeleUnavailable(f"Fedele returned {reason}")

        if response.status_code in (401, 403):
            log.error(
                f"Fedele rejected the request with HTTP {response.status_code} on "
                f"'{path}': check FEDELE_TOKEN and its scope. The circuit breaker "
                f"stays closed — this does not heal on its own."
            )
            raise FedeleConfigError(
                f"Fedele rejected the request with HTTP {response.status_code} on {path}. "
                f"Check FEDELE_TOKEN and its scope."
            )

        if response.status_code != 200:
            log.warning(
                f"Fedele returned HTTP {response.status_code} on '{path}' "
                f"params={params or {}}"
            )
            raise FedeleError(f"Fedele returned HTTP {response.status_code} on {path}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise FedeleError(f"Fedele returned a non-JSON response on {path}") from exc

        self.reset_breaker()
        return payload


fedele_client: FedeleClient | None = None
fedele_client_lock = threading.Lock()


def get_fedele_client() -> FedeleClient:
    """Devuelve el cliente Fedele compartido, construyéndolo si hace falta.

    Levanta FedeleConfigError si falta FEDELE_URL o FEDELE_TOKEN. Los llamadores
    lo traducen a su propio tipo de error (CredentialError o InventoryError) para
    que el mensaje que llegue al operador nombre el subsistema afectado.
    """
    global fedele_client
    if fedele_client is None:
        with fedele_client_lock:
            if fedele_client is None:
                fedele_client = FedeleClient()
    return fedele_client


CREDENTIAL_FIELDS: tuple[str, ...] = ("username", "password", "secret")

INTERNAL_FIELDS: tuple[str, ...] = ("fedele_id",)


class CredentialError(Exception):
    """La credencial de un dispositivo no pudo resolverse.

    Se lanza en la resolución, no al conectar: un intento de login con la
    credencial equivocada es peor que un error claro. Contra TACACS+, los
    intentos fallidos repetidos bloquean la cuenta de servicio.

    El mensaje nombra qué falta (variable, objeto), nunca un valor.
    """


class EnvCredentialProvider:
    """Credenciales desde el entorno del proceso.

    Dentro de Niko, build_mcp_process_env carga el .env del proyecto y copia
    os.environ al subprocess, así que las variables llegan sin configuración
    adicional.
    """

    name = "env"

    def get_credentials(self, device_name: str, device: dict[str, Any]) -> dict[str, str]:
        username = (os.getenv("NETMIKO_USERNAME") or "").strip()
        password = os.getenv("NETMIKO_PASSWORD") or ""
        secret = os.getenv("NETMIKO_SECRET") or ""

        missing = [
            var
            for var, value in (("NETMIKO_USERNAME", username), ("NETMIKO_PASSWORD", password))
            if not value
        ]
        if missing:
            raise CredentialError(
                f"credential_source=env but {', '.join(missing)} is missing from the "
                f"environment. Set it in the project's .env."
            )

        creds = {"username": username, "password": password}
        if secret:
            creds["secret"] = secret
        log_credential_resolution(
            device=device_name, source=self.name, credential_ref="NETMIKO_USERNAME"
        )
        return creds


class FedeleCredentialProvider:
    """Credenciales desde el plugin `fedele_credentials` del SoT.

    Resolución en dos saltos, verificada contra el plugin v0.0.4:

        GET dcim/devices/?name=<nombre>                          → device.id
        GET plugins/credentials/devicecredentials/?device=<id>   → .credential
        GET plugins/credentials/networkcredentials/<cred_id>/    → username, password

    `devicecredentials` es una tabla de join pura ({device, credential}); el
    objeto con los datos es `networkcredentials`.

    Dos campos vienen cifrados como base64 de un token Fernet, ambos read-only
    en el serializer: `password` y `enabled`. Este último es el **enable
    password** (modo privilegiado), lo que Netmiko llama `secret` — no un
    indicador de habilitación.

    No hay descifrado del lado del servidor: `?decrypt=true` y `?plaintext=true`
    devuelven el mismo valor cifrado, y no existe endpoint de desbloqueo
    (verificado: get-session-key, session-key, user-key, keys y decrypt dan 404).
    El descifrado ocurre acá, con la clave en FEDELE_CREDENTIALS_KEY.
    """

    name = "fedele"

    def __init__(self) -> None:
        try:
            self.client = get_fedele_client()
        except FedeleConfigError as exc:
            raise CredentialError(f"credential_source=fedele: {exc}") from exc
        self.cache = TTLCache(settings.fedele_cache_ttl)
        key = (os.getenv("FEDELE_CREDENTIALS_KEY") or "").strip()
        if not key:
            raise CredentialError(
                "credential_source=fedele requires FEDELE_CREDENTIALS_KEY in the environment "
                "(the Fernet key of the fedele_credentials plugin). Without it the server can "
                "read which credential belongs to each device, but not decrypt it. "
                "Alternative: NETMIKO_MCP_CREDENTIAL_SOURCE=env."
            )
        try:
            self.fernet = Fernet(key.encode() if isinstance(key, str) else key)
        except Exception as exc:
            raise CredentialError(
                f"FEDELE_CREDENTIALS_KEY is not a valid Fernet key: {type(exc).__name__}"
            ) from exc


    def device_id_of(self, device_name: str) -> int:
        """ID del dispositivo en Fedele, a partir de su nombre de inventario."""
        payload = self.client.get("dcim/devices/", {"name": device_name})
        results = payload.get("results") or []
        exact = [r for r in results if r.get("name") == device_name]
        if not exact:
            raise CredentialError(
                f"Device '{device_name}' does not exist in Fedele "
                f"(dcim/devices?name={device_name})."
            )
        if len(exact) > 1:
            raise CredentialError(
                f"Fedele returned {len(exact)} devices with the exact name "
                f"'{device_name}'. An ambiguous name is not resolved by elimination."
            )
        return int(exact[0]["id"])

    def credential_id_of(self, device_name: str, device_id: int) -> int:
        """ID de la credencial asociada al dispositivo, vía la tabla de join.

        VERIFICADO: `?device=<id>` filtra bien, pero `?device_id=<id>` NO — el
        parámetro no reconocido se ignora en silencio y el endpoint devuelve
        TODOS los joins. Por eso no alcanza con confiar en el filtro: hay que
        comprobar que cada registro devuelto sea realmente de este dispositivo.
        Sin esa comprobación, un rename del filtro upstream se manifestaría como
        conexiones con las credenciales de otro equipo.
        """
        payload = self.client.get(
            "plugins/credentials/devicecredentials/", {"device": device_id}
        )
        results = payload.get("results") or []
        matching = [r for r in results if r.get("device") == device_id]

        if len(matching) != len(results):
            log.warning(
                f"Fedele: the ?device={device_id} filter returned {len(results)} records, "
                f"only {len(matching)} of which belong to the device. The filterset may "
                f"have changed; falling back to the local check."
            )

        if not matching:
            raise CredentialError(
                f"Device '{device_name}' (Fedele id={device_id}) has no credential "
                f"associated in the credentials plugin."
            )
        if len(matching) > 1:
            credential_ids = sorted({r.get("credential") for r in matching})
            if len(credential_ids) > 1:
                raise CredentialError(
                    f"Device '{device_name}' has {len(credential_ids)} different credentials "
                    f"associated in Fedele (ids: {credential_ids}). Picking one by elimination "
                    f"would mean attempting the login with the wrong one."
                )
        return int(matching[0]["credential"])

    def credential_record(self, credential_id: int) -> dict[str, Any]:
        """Objeto networkcredentials completo (username en claro, password cifrado)."""
        return self.client.get(f"plugins/credentials/networkcredentials/{credential_id}/")


    def decrypt_field(self, value: str, field: str) -> str:
        """Descifra un campo del plugin: base64 por fuera, Fernet por dentro.

        El mensaje de error nunca incluye el valor, ni cifrado ni descifrado.
        """
        try:
            token = base64.b64decode(value, validate=True)
        except Exception as exc:
            raise CredentialError(
                f"Credential field '{field}' is not valid base64 "
                f"({type(exc).__name__}). Did the plugin format change?"
            ) from exc
        try:
            return self.fernet.decrypt(token).decode("utf-8")
        except Exception as exc:
            raise CredentialError(
                f"Could not decrypt credential field '{field}' "
                f"({type(exc).__name__}). Check that FEDELE_CREDENTIALS_KEY is the key from "
                f"the PLUGINS_CONFIG of this Fedele server."
            ) from exc


    def get_credentials(self, device_name: str, device: dict[str, Any]) -> dict[str, str]:
        cached = self.cache.get(device_name)
        if cached is not None:
            return dict(cached)

        device_id = device.get("fedele_id")
        if device_id is None:
            device_id = self.device_id_of(device_name)

        credential_id = self.credential_id_of(device_name, int(device_id))
        record = self.credential_record(credential_id)

        username = (record.get("username") or "").strip()
        password_raw = record.get("password") or ""
        if not username or not password_raw:
            raise CredentialError(
                f"La credencial id={credential_id} de '{device_name}' no trae username o "
                f"password utilizables."
            )

        creds = {"username": username, "password": self.decrypt_field(password_raw, "password")}

        enable_raw = record.get("enabled") or ""
        if enable_raw:
            creds["secret"] = self.decrypt_field(enable_raw, "enabled")

        self.cache.set(device_name, dict(creds))
        log_credential_resolution(
            device=device_name,
            source=self.name,
            credential_ref=f"networkcredentials/{credential_id} ({record.get('name')})",
        )
        return creds


def build_credential_provider() -> Any:
    """Devuelve el proveedor de credenciales según credential_source.

    La elección es explícita por configuración. No hay detección automática ni
    fallback silencioso: que el mismo dispositivo se conecte con credenciales
    distintas según qué servicio estuviera arriba es exactamente el tipo de
    ambigüedad que no queremos sobre un equipo de red.

    La construcción se difiere si falla: un error de configuración de
    credenciales no debe impedir que el servidor arranque, porque entonces Niko
    solo vería un timeout de 30 segundos. Se reporta por startup_error y por
    cada tool.
    """
    if settings.credential_source == "fedele":
        return FedeleCredentialProvider()
    return EnvCredentialProvider()


class DeferredCredentialProvider:
    """Placeholder que relanza el error de construcción en cada uso.

    Si el proveedor real no se pudo construir (falta una variable, la clave es
    inválida), el módulo tiene que importarse igual: Niko arranca este archivo
    como subprocess y necesita que el servidor levante para poder reportar el
    problema por las tools. Fallar al importar se ve, del lado de Niko,
    exactamente igual que un servidor que nunca arrancó.
    """

    name = "unavailable"

    def __init__(self, error: Exception) -> None:
        self.error = error

    def get_credentials(self, device_name: str, device: dict[str, Any]) -> dict[str, str]:
        raise CredentialError(str(self.error))


DEFAULT_ALLOWED_COMMANDS: list[str] = []
DEFAULT_DENIED_COMMANDS: list[str] = []

POLICY_SOURCE_FILE = "file"
POLICY_SOURCE_FALLBACK = "fallback"


@dataclass
class ValidationResult:
    """Resultado de validate_command.

    allowed indica si el comando debe permitirse. reason es una de las
    constantes REASON_* y describe por qué fue permitido o denegado; se registra
    verbatim en el audit log.

    normalized_command es la forma con whitespace normalizado del comando
    enviado. Cuando allowed es True, es el string exacto que hay que reenviar al
    dispositivo.
    """

    allowed: bool
    reason: str
    normalized_command: str = ""


class TrieNode:
    """Nodo de un árbol de prefijos a nivel carácter para una palabra de comando.

    children mapea cada carácter al siguiente TrieNode de este nivel de palabra.

    word_end marca el fin de una palabra completa de una entrada deny.

    final_word marca la última palabra de una entrada deny simple (sin glob).

    glob_suffix marca la última palabra de una entrada con glob inline (p. ej.
      "interface*"). La palabra enviada puede ser prefijo del stem o extenderse
      más allá, y también se admiten palabras extra.

    glob_next_word marca la última palabra antes de un glob con espacio (p. ej.
      "interface *"). La palabra enviada debe ser prefijo del stem únicamente, y
      se requiere al menos una palabra adicional.

    next_word_trie es la raíz del trie de la siguiente palabra en una entrada
    deny multi-palabra.
    """

    def __init__(self) -> None:
        self.children: dict[str, TrieNode] = {}
        self.word_end: bool = False
        self.final_word: bool = False
        self.glob_suffix: bool = False
        self.glob_next_word: bool = False
        self.next_word_trie: TrieNode | None = None


class AbbreviationDenyFilter:
    """Determina si un comando enviado es abreviatura de alguna entrada simple
    (sin glob) del denied_commands.

    Cada entrada deny se indexa en una jerarquía de nodos a nivel carácter, un
    índice por palabra. En cada nivel la palabra enviada puede matchear como
    prefijo de la palabra deny, así 'sh ver' matchea 'show version'.

    Un comando enviado queda denegado si:
    - Cada palabra de la entrada deny matchea con la palabra correspondiente del
      comando enviado, incluyendo prefijos (case-insensitive), Y
    - El comando enviado tiene exactamente la misma cantidad de palabras.

    Las palabras extra NO están cubiertas: 'sh ver sum' NO queda denegado por
    'show version'. Para cubrir argumentos adicionales hay que usar un glob.

    Las primeras palabras abreviadas están cubiertas por las tres formas, pero
    las reglas de cantidad de palabras siguen aplicando:
      - simple 'show ip interface'       deniega 'sh ip int' (exactamente 3
                                         palabras), pero NO 'sh ip int brief'.
      - glob inline 'show ip interface*' deniega ambos.
      - glob espacio 'show ip interface *' deniega 'sh ip int brief' (la palabra
                                         extra satisface el *), pero NO
                                         'sh ip int' solo.

    Se construye una vez al cargar con add(), y se consulta por comando con
    is_denied().
    """

    def __init__(self) -> None:
        self.root = TrieNode()

    def add(self, deny_entry: str) -> None:
        """Inserta una entrada deny (simple o con glob final) en la jerarquía.

        Formas soportadas:
          simple:       "show ip interface"   — match exacto de cantidad de palabras.
          glob inline:  "show ip interface*"  — stem de la última palabra + los
                                                caracteres o palabras que sigan.
          glob espacio: "show ip interface *" — última palabra solo por prefijo,
                                                requiere al menos una palabra más.

        Las entradas con globs no soportados las rechaza validate_command_lists()
        al arrancar, antes de que lleguen acá.
        """
        words = deny_entry.strip().lower().split()
        if not words:
            return

        last = words[-1]

        if last == "*":
            prefix_words = words[:-1]
            if not prefix_words:
                return
            if any("*" in w for w in prefix_words):
                return
            is_inline_glob = False
            is_space_glob = True
            effective_words = prefix_words
        elif last.endswith("*"):
            base_word = last[:-1]
            if not base_word:
                return
            if any("*" in w for w in words[:-1]):
                return
            is_inline_glob = True
            is_space_glob = False
            effective_words = words[:-1] + [base_word]
        else:
            if "*" in deny_entry:
                return
            is_inline_glob = False
            is_space_glob = False
            effective_words = words

        node = self.root
        for word_idx, word in enumerate(effective_words):
            for char in word:
                if char not in node.children:
                    node.children[char] = TrieNode()
                node = node.children[char]
            node.word_end = True
            is_last = word_idx == len(effective_words) - 1
            if is_last:
                if is_inline_glob:
                    node.glob_suffix = True
                elif is_space_glob:
                    node.glob_next_word = True
                else:
                    node.final_word = True
            else:
                if node.next_word_trie is None:
                    node.next_word_trie = TrieNode()
                node = node.next_word_trie

    def is_denied(self, submitted: str) -> bool:
        """True si submitted es abreviatura de alguna entrada deny.

        submitted debe ser el comando ya normalizado. La comparación es
        case-insensitive.
        """
        words = submitted.strip().lower().split()
        if not words:
            return False
        return self.match_word(trie_root=self.root, words=words, word_idx=0)

    def match_word(self, trie_root: TrieNode, words: list[str], word_idx: int) -> bool:
        """Recorre trie_root con los caracteres de words[word_idx], después hace
        DFS buscando nodos terminales alcanzables y evalúa la lógica de deny.

        match_word y find_word_end se llaman mutuamente para encadenar por las
        sucesivas palabras de una entrada deny multi-palabra.
        """
        node = trie_root
        for char in words[word_idx]:
            if node.glob_suffix:
                return True
            if char not in node.children:
                return False
            node = node.children[char]
        last_word = word_idx == len(words) - 1
        return self.find_word_end(
            node=node,
            words=words,
            word_idx=word_idx,
            last_word=last_word,
        )

    def find_word_end(
        self,
        node: TrieNode,
        words: list[str],
        word_idx: int,
        last_word: bool,
    ) -> bool:
        """DFS desde node buscando nodos terminales alcanzables y aplicando la
        lógica de deny.

        La palabra enviada para word_idx terminó en algún punto dentro de la
        palabra del patrón deny.

        La palabra enviada puede ser prefijo de una palabra deny más larga, así
        que hacemos DFS para encontrar todas las palabras deny completas
        alcanzables desde la posición actual.

        match_word y find_word_end se llaman mutuamente para encadenar por las
        sucesivas palabras de una entrada deny multi-palabra.

        find_word_end también recurre sobre sí misma para hacer DFS por los
        hijos-carácter cuando la palabra enviada termina a mitad de un patrón.
        """
        if node.word_end:
            if node.final_word and last_word:
                return True
            if node.glob_suffix:
                return True
            if node.glob_next_word and not last_word:
                return True
            if not last_word and node.next_word_trie is not None:
                if self.match_word(
                    trie_root=node.next_word_trie, words=words, word_idx=word_idx + 1
                ):
                    return True
        for child in node.children.values():
            if self.find_word_end(
                node=child,
                words=words,
                word_idx=word_idx,
                last_word=last_word,
            ):
                return True
        return False


def invalid_glob_entries(entries: list[str]) -> list[str]:
    """Devuelve las entradas que violan la regla de un único glob final.

    Ambas listas comparten la regla: como máximo un '*', y solo como palabra
    final ('cmd *') o carácter final ('cmd*'). Un '*' solo, sin prefijo, también
    es inválido.

    Formas inválidas:
      - Un '*' solo (sin palabras de prefijo).
      - '*' en cualquier posición de palabra no final ('show * interface').
      - '*' a mitad de una palabra no final ('sh*w version').
      - Más de un '*' en la entrada.
    """
    invalid = []
    for entry in entries:
        words = entry.strip().split()
        if not words:
            continue
        if entry.count("*") > 1:
            invalid.append(entry)
            continue
        last = words[-1]
        if last == "*":
            prefix_words = words[:-1]
            if not prefix_words or any("*" in w for w in prefix_words):
                invalid.append(entry)
        elif last.endswith("*"):
            if not last[:-1] or any("*" in w for w in words[:-1]):
                invalid.append(entry)
        elif "*" in entry:
            invalid.append(entry)
    return invalid


def validate_allow_commands(allowed_commands: list[str]) -> list[str]:
    """Devuelve las entradas allow con patrones glob no soportados.

    Un glob mal formado del lado allow es un agujero de seguridad: puede
    permitir comandos que no deberían permitirse. Se reportan como errores de
    arranque.
    """
    return invalid_glob_entries(entries=allowed_commands)


def validate_deny_commands(denied_commands: list[str]) -> list[str]:
    """Devuelve las entradas deny con patrones glob no soportados.

    Un glob mal formado del lado deny lo ignoraría AbbreviationDenyFilter en
    silencio, dejando de denegar comandos que debería. Se reportan como errores
    de arranque.
    """
    return invalid_glob_entries(entries=denied_commands)


def validate_command_lists(
    allowed_commands: list[str],
    denied_commands: list[str],
) -> list[str]:
    """Valida ambas listas y devuelve todos los mensajes de error.

    Devuelve una lista vacía cuando ambas son válidas. Cada entrada es un
    mensaje legible que dice qué lista tiene el problema y cuáles entradas son
    inválidas.
    """
    errors: list[str] = []
    invalid_allow = validate_allow_commands(allowed_commands=allowed_commands)
    if invalid_allow:
        errors.append(
            f"allowed_commands contains unsupported glob pattern(s): {invalid_allow}. "
            f"'*' must appear only as a trailing word ('cmd *') or trailing character ('cmd*')."
        )
    invalid_deny = validate_deny_commands(denied_commands=denied_commands)
    if invalid_deny:
        errors.append(
            f"denied_commands contains unsupported glob pattern(s): {invalid_deny}. "
            f"'*' must appear only as a trailing word ('cmd *') or trailing character ('cmd*')."
        )
    return errors


def glob_to_regex(glob_pattern: str) -> re.Pattern[str]:
    """Convierte un glob simple con '*' en una expresión regular compilada.

    El comodín '*' matchea cualquier carácter. Los comandos se validan contra
    allowed_command_chars antes de llegar acá, así que no hace falta ninguna
    restricción adicional sobre el comodín.

    Un ' *' final (espacio y asterisco) requiere al menos una palabra adicional
    después del prefijo. Como los comandos siempre se normalizan a un espacio
    antes de validar, alcanza con un espacio literal seguido de .*
    'show version *' matchea 'show version brief' pero NO 'show version' solo.
    Para matchear también el comando base, usar 'show version*' (glob inline).
    """
    escaped = re.escape(glob_pattern.strip())
    escaped = escaped.replace(r"\ \*", r"\ .*")
    escaped = escaped.replace(r"\*", r".*")

    return re.compile("^" + escaped + "$", re.IGNORECASE)


def deny_check(command: str, denied_commands: list[str]) -> bool:
    """True si el comando matchea alguna entrada de denied_commands.

    Cada entrada se evalúa vía glob_to_regex — la misma lógica que el chequeo de
    allow.

    Deny siempre tiene precedencia sobre allow.
    """
    for denied in denied_commands:
        if glob_to_regex(denied.strip()).match(command):
            return True
    return False


class CommandPolicyError(Exception):
    """The command file exists but cannot be used as a policy."""


@lru_cache(maxsize=1)
def load_commands() -> dict[str, Any]:
    """Load the allow/deny list from the configured command_file.

    Cached after the first call: the server has to be restarted to pick up edits
    to commands.yml.

    When the file does not exist, the built-in FALLBACK_ALLOWED_COMMANDS applies
    instead of an empty policy. An empty policy denies every command while the
    server keeps reporting itself healthy, which reads as "the device refused"
    rather than "nobody wrote a policy". The fallback is announced — see
    command_policy_warning() — and every audited attempt carries its source.

    The file branch drops any `policy_source` key the YAML may carry, so a policy
    file cannot claim to be the fallback (or the other way round). This function
    is the only place that decides which of the two is in force.
    """
    file_path = Path(settings.command_file).expanduser()
    if file_path.is_file():
        commands = load_yaml_file(str(file_path))
        if not isinstance(commands, dict):
            # An existing-but-unusable file is NOT the fallback. The fallback answers
            # "nobody wrote a policy yet"; a 0-byte or malformed commands.yml answers
            # "somebody wrote one and it is broken", and widening the allow list on
            # the strength of a broken file is exactly the wrong reflex. Raising here
            # keeps the invariant this function owns — it returns a mapping or nothing
            # at all — so no caller has to defend against None. validate_startup()
            # turns it into a startup error that names the file, and every tool then
            # reports that instead of touching a device.
            raise CommandPolicyError(
                f"the file is empty or its top level is not a mapping "
                f"(YAML parsed as {type(commands).__name__})"
            )
        commands.pop("policy_source", None)
        return commands
    return {
        "allowed_commands": list(FALLBACK_ALLOWED_COMMANDS),
        "denied_commands": [],
        "policy_source": POLICY_SOURCE_FALLBACK,
    }


def command_policy_source() -> str:
    """POLICY_SOURCE_FILE or POLICY_SOURCE_FALLBACK, from the loaded policy.

    Derived from load_commands() rather than probing the filesystem again: the
    load is cached, so a second stat could disagree with the policy actually in
    memory if the file appeared or vanished in between.
    """
    return str(load_commands().get("policy_source", POLICY_SOURCE_FILE))


def command_policy_warning() -> str | None:
    """The message to surface while the fallback policy is in force, or None.

    Names the resolved path — not a literal — because that path depends on
    CONFIG_PATH and on which extension the operator uses (see
    command_file_name()). Telling someone to create a file at the wrong path is
    worse than saying nothing.
    """
    if command_policy_source() != POLICY_SOURCE_FALLBACK:
        return None
    return (
        f"Fallback command policy in force: '{settings.command_file}' does not exist, "
        f"so only the built-in read-only commands are allowed "
        f"({', '.join(FALLBACK_ALLOWED_COMMANDS)}). "
        f"Create that file with your allowed_commands and restart the server."
    )


@lru_cache(maxsize=128)
def build_abbreviation_filter(denied_commands: tuple[str, ...]) -> AbbreviationDenyFilter:
    """Construye y cachea un AbbreviationDenyFilter desde denied_commands.

    Todas las entradas deny se cargan en el trie — simples, con glob inline y
    con glob de espacio. El trie maneja el matcheo de abreviaturas para las tres
    formas, de modo que las primeras palabras abreviadas quedan cubiertas. El
    camino por regex de deny_check() sigue cubriendo los matches exactos y de
    glob para comandos completamente expandidos.

    El caché se indexa por la tupla denied_commands, así distintas
    configuraciones obtienen filtros independientes sin necesidad de reiniciar
    cuando los tests proveen datos mock distintos.
    """
    deny_filter = AbbreviationDenyFilter()
    for entry in denied_commands:
        deny_filter.add(deny_entry=entry)
    return deny_filter


def validate_command(command: str) -> ValidationResult:
    """Valida que el comando pedido sea seguro de ejecutar.

    Devuelve un ValidationResult con allowed=True y reason=REASON_ALLOWED si
    pasa todos los chequeos, o allowed=False con la constante específica que
    indica por qué fue rechazado. El motivo lo registra el llamador en el audit
    log. normalized_command es la forma normalizada que hay que reenviar al
    dispositivo cuando está permitido.

    Reglas, en orden:
    - Se normaliza el whitespace: runs ASCII colapsados a un espacio, strip de
      los extremos.
    - El comando solo puede contener caracteres de allowed_command_chars (más
      '|' cuando allow_pipe es True). Rechaza homoglifos Unicode del espacio y
      caracteres de inyección.
    - El comando NO debe matchear ninguna entrada de denied_commands (se evalúa
      el comando base, antes de cualquier pipe; soporta globs).
    - Si hay pipe, allow_pipe debe ser True y el modificador debe estar en
      pipe_modifiers. Múltiples pipes se rechazan siempre.
    - El comando base debe matchear alguna entrada de allowed_commands.
    """
    commands = load_commands()

    allowed_commands = commands.get("allowed_commands", DEFAULT_ALLOWED_COMMANDS)
    denied_commands = commands.get("denied_commands", DEFAULT_DENIED_COMMANDS)

    normalized = " ".join(command.split())

    effective_allowed = set(settings.allowed_command_chars)
    if settings.allow_pipe:
        effective_allowed.add("|")
    if any(c not in effective_allowed for c in normalized):
        return ValidationResult(
            allowed=False, reason=REASON_UNSAFE_CHAR, normalized_command=normalized
        )

    parts = normalized.split("|", 1)
    base_command = parts[0].strip()

    if deny_check(command=base_command, denied_commands=denied_commands):
        return ValidationResult(
            allowed=False, reason=REASON_DENY_MATCH, normalized_command=normalized
        )
    if build_abbreviation_filter(denied_commands=tuple(denied_commands)).is_denied(
        submitted=base_command
    ):
        return ValidationResult(
            allowed=False, reason=REASON_DENY_MATCH, normalized_command=normalized
        )

    if len(parts) > 1:
        pipe_modifier = parts[1].strip().lower()

        if "|" in pipe_modifier:
            return ValidationResult(
                allowed=False, reason=REASON_MULTIPLE_PIPES, normalized_command=normalized
            )

        if pipe_modifier:
            modifier_keyword = pipe_modifier.split()[0]
            if modifier_keyword not in settings.pipe_modifiers:
                return ValidationResult(
                    allowed=False,
                    reason=REASON_INVALID_PIPE_MODIFIER,
                    normalized_command=normalized,
                )
        else:
            return ValidationResult(
                allowed=False, reason=REASON_INVALID_PIPE_MODIFIER, normalized_command=normalized
            )

    for allowed in allowed_commands:
        if "*" in allowed:
            pattern = glob_to_regex(allowed)
            if pattern.match(base_command):
                return ValidationResult(
                    allowed=True, reason=REASON_ALLOWED, normalized_command=normalized
                )
        elif base_command.lower() == allowed.strip().lower():
            return ValidationResult(
                allowed=True, reason=REASON_ALLOWED, normalized_command=normalized
            )

    return ValidationResult(
        allowed=False, reason=REASON_NO_ALLOW_MATCH, normalized_command=normalized
    )


class InventoryError(Exception):
    """El dispositivo o grupo no pudo resolverse contra el inventario."""


def strip_inventory_credentials(device_name: str, params: dict[str, Any]) -> dict[str, Any]:
    """Quita credenciales que vengan del archivo de inventario.

    Las credenciales se resuelven en la §6, nunca desde disco. Si el YAML
    las trae igual, se ignoran con warning en vez de dejarlas ganar por
    precedencia: un password olvidado en un archivo que entra en efecto sin que
    nadie lo note es peor que un error.
    """
    clean = dict(params)
    found = [field for field in CREDENTIAL_FIELDS if clean.pop(field, None) not in (None, "")]
    if found:
        log.warning(
            f"Inventory: device '{device_name}' carries {', '.join(found)} in the file; "
            f"ignored. Credentials are resolved through credential_source="
            f"{settings.credential_source}."
        )
    return clean


class YamlInventoryBackend:
    """Inventario local en formato netmiko_tools.

    Es el backend de respaldo: se usa con inventory_type=yaml (o netmiko_tools)
    cuando Fedele está fuera de servicio o en entornos de laboratorio. Mantenerlo
    vigente con scripts/export_inventory.py — un inventario de respaldo que nadie
    actualiza tiene direcciones viejas justo el día que hace falta.
    """

    name = "yaml"

    def __init__(self) -> None:
        self.last_excluded: dict[str, str] = {}

    def set_inventory_env_var(self) -> None:
        """Apunta obtain_devices al archivo de inventario de nuestra config.

        Si inventory_file está definido, se sobrescribe NETMIKO_TOOLS_CFG. Si no,
        se deja como está para que Netmiko siga su búsqueda nativa.

        Muta os.environ, que es un efecto colateral global. Dentro de Niko cada
        MCP corre en su propio subprocess, así que el alcance queda contenido a
        este proceso.
        """
        if settings.inventory_file:
            inventory_path = Path(settings.inventory_file).expanduser()
            os.environ["NETMIKO_TOOLS_CFG"] = str(inventory_path)

    def obtain(self, target: str) -> dict[str, Any]:
        """Envuelve obtain_devices normalizando su manejo de errores.

        Netmiko devuelve un string con el mensaje de error cuando no encuentra el
        dispositivo o grupo, en vez de lanzar. Lo convertimos en InventoryError
        para que el resto del código tenga un solo camino de falla.
        """
        self.set_inventory_env_var()
        devices = obtain_devices(target)
        if isinstance(devices, str):
            raise InventoryError(devices)
        return devices

    def list_groups(self) -> list[str]:
        """Nombres de grupo del inventario.

        Los grupos son las claves de primer nivel cuyo valor es una lista de
        nombres de dispositivo. Las entradas de dispositivo (valor dict) y el
        bloque __meta__ quedan excluidos.
        """
        self.set_inventory_env_var()
        try:
            cfg_file = find_cfg_file()
        except ValueError as e:
            raise InventoryError(f"Inventory file not found: {e}") from e
        raw = load_yaml_file(cfg_file)
        return [k for k, v in raw.items() if isinstance(v, list) and k != "__meta__"]

    def resolve_device(self, device_name: str) -> dict[str, Any]:
        """Parámetros de conexión de un dispositivo, sin credenciales."""
        devices = self.obtain(device_name)
        if device_name not in devices:
            raise InventoryError(f"Device '{device_name}' not found in inventory.")
        return strip_inventory_credentials(device_name, devices[device_name])

    def resolve_group(self, device_or_group: str) -> list[str]:
        """Nombres de dispositivo de un grupo (o el dispositivo mismo)."""
        return list(self.obtain(device_or_group).keys())

    def all_devices(self, device_or_group: str) -> dict[str, dict[str, Any]]:
        """Parámetros de todos los dispositivos de un grupo, en una sola lectura.

        Evita releer y redescifrar el inventario dentro de cada hilo, que
        serializaría las conexiones concurrentes de un comando de grupo.
        """
        return {
            name: strip_inventory_credentials(name, params)
            for name, params in self.obtain(device_or_group).items()
        }

    def source_info(self) -> dict[str, Any]:
        """Procedencia del inventario, para netmiko.get_metadata.

        Incluye la antigüedad del archivo: cuando el operador conmuta a este
        backend porque Fedele no responde, necesita ver "última modificación hace
        ocho meses" antes de correr nada, no después.
        """
        info: dict[str, Any] = {"backend": self.name, "file": settings.inventory_file}
        if settings.inventory_file:
            path = Path(settings.inventory_file).expanduser()
            if path.is_file():
                mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
                age_days = (datetime.now(UTC) - mtime).days
                info["last_modified"] = mtime.isoformat()
                info["age_days"] = age_days
                if age_days > 30:
                    info["warning"] = (
                        f"The local inventory has not been updated in {age_days} days. "
                        f"Check the addresses before operating."
                    )
            else:
                info["warning"] = "The configured inventory file does not exist."
        return info


EXCLUDED_NO_IP = "no primary_ip"
EXCLUDED_NO_PLATFORM = "no platform"
EXCLUDED_PLATFORM_UNSUPPORTED = "platform is not a netmiko device_type"

GROUP_SOURCES: dict[str, tuple[str, str]] = {
    "tags": ("tag", "extras/tags/"),
    "device_roles": ("role", "dcim/device-roles/"),
    "sites": ("site", "dcim/sites/"),
}


class FedeleInventoryBackend:
    """Inventario dinámico resuelto contra el SoT.

    Las tools siguen recibiendo un NOMBRE de dispositivo; lo único que cambia
    respecto del backend YAML es de dónde sale la dirección. El LLM nunca provee
    un host, así que el inventario sigue siendo la frontera de confianza.

    De los tres campos que hacen falta para conectar:
      - `host`         sale de primary_ip.address, sin la máscara.
      - `device_type`  sale de platform.name, VALIDADO contra CLASS_MAPPER.
      - credenciales   las resuelve la §6, no este backend.

    Un dispositivo sin primary_ip, sin platform, o con una platform que no es un
    device_type de Netmiko queda EXCLUIDO del inventario. No es un detalle
    teórico: el SoT también inventaría cosas que no son equipos de red
    gestionables por SSH — cámaras, control de acceso, balanceadores, chasis UCS.
    Intentar `ConnectHandler(device_type='CCTV_camera')` no falla con un mensaje
    útil, falla raro.

    Las exclusiones se cuentan y se informan. Un inventario que devuelve 24 de 61
    equipos sin decirlo haría que el modelo afirme "estos son todos los
    dispositivos" con total confianza.
    """

    name = "fedele"

    PAGE_SIZE = 250
    MAX_PAGES = 40

    def __init__(self) -> None:
        try:
            self.client = get_fedele_client()
        except FedeleConfigError as exc:
            raise InventoryError(f"inventory_type=fedele: {exc}") from exc
        self.cache = TTLCache(settings.fedele_cache_ttl)
        if settings.fedele_group_source not in GROUP_SOURCES:
            raise InventoryError(
                f"fedele_group_source='{settings.fedele_group_source}' is not valid. "
                f"Options: {', '.join(GROUP_SOURCES)}."
            )
        self.group_param, self.group_endpoint = GROUP_SOURCES[settings.fedele_group_source]
        self.last_excluded: dict[str, str] = {}
        self.scope = self.parse_scope_filter(settings.fedele_device_filter)
        if not self.scope:
            log.warning(
                "Fedele: NETMIKO_MCP_FEDELE_DEVICE_FILTER is not set. The inventory covers "
                "EVERY device the SoT knows about. Narrowing it with a filter "
                "(for example 'tag=lab') limits the scope of what the agent can reach."
            )

    @staticmethod
    def parse_scope_filter(raw: str | None) -> dict[str, str]:
        """Convierte 'tag=lab&status=active' en parámetros de consulta.

        El filtro de alcance es lo que evita que el inventario dinámico sea todo
        el parque. Se aplica a TODAS las consultas de dispositivos.
        """
        if not raw or not raw.strip():
            return {}
        scope: dict[str, str] = {}
        for chunk in raw.split("&"):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "=" not in chunk:
                raise InventoryError(
                    f"fedele_device_filter='{raw}' is not in key=value form "
                    f"(the '{chunk}' fragment carries no '=')."
                )
            key, value = chunk.split("=", 1)
            scope[key.strip()] = value.strip()
        return scope


    def get_paginated(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Trae todas las páginas de un listado.

        Fedele devuelve 50 registros por defecto y señala el resto con `next`.
        Sin esto, un grupo de 60 equipos se resolvería a 50 sin ningún aviso.
        """
        results: list[dict[str, Any]] = []
        offset = 0
        for page_number in range(self.MAX_PAGES):
            payload = self.client.get(
                path, {**params, "limit": self.PAGE_SIZE, "offset": offset}
            )
            page = payload.get("results") or []
            results.extend(page)
            if not payload.get("next") or not page:
                return results
            offset += self.PAGE_SIZE
        log.warning(
            f"Fedele: {path} went past {self.MAX_PAGES} pages; the listing was truncated "
            f"at {len(results)} records."
        )
        return results

    def query_devices(self, **filters: Any) -> list[dict[str, Any]]:
        """Dispositivos que cumplen el filtro, dentro del alcance configurado."""
        return self.get_paginated("dcim/devices/", {**self.scope, **filters})


    @staticmethod
    def host_of(record: dict[str, Any]) -> str | None:
        """Dirección de gestión sin la máscara ('10.2.3.106/24' → '10.2.3.106')."""
        primary_ip = record.get("primary_ip") or {}
        address = (primary_ip.get("address") or "").strip()
        if not address:
            return None
        return address.split("/", 1)[0]

    @staticmethod
    def device_type_of(record: dict[str, Any]) -> tuple[str | None, str | None]:
        """(device_type, motivo_de_exclusión).

        Fedele guarda en `platform.name` el identificador de Netmiko tal cual, así
        que NO hay tabla de mapeo. Pero sí hay validación, y no es decorativa: el
        SoT también inventaría equipamiento que no se gestiona por SSH, y esas
        plataformas ('CCTV_camera', 'lenel', 'bigip', 'ucs') no son device_types
        de Netmiko. CLASS_MAPPER es la lista autoritativa, no una copia nuestra
        que haya que mantener.
        """
        platform = record.get("platform") or {}
        name = (platform.get("name") or "").strip()
        if not name:
            return None, EXCLUDED_NO_PLATFORM
        if name not in CLASS_MAPPER:
            return None, EXCLUDED_PLATFORM_UNSUPPORTED
        return name, None

    def to_params(self, record: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
        """Convierte un registro de Fedele en parámetros de conexión.

        Devuelve (params, None) si el equipo es gestionable, o (None, motivo) si
        hay que excluirlo.
        """
        host = self.host_of(record)
        if not host:
            return None, EXCLUDED_NO_IP
        device_type, reason = self.device_type_of(record)
        if not device_type:
            return None, reason
        return {
            "host": host,
            "device_type": device_type,
            "fedele_id": record.get("id"),
        }, None


    def list_groups(self) -> list[str]:
        """Nombres de grupo, según fedele_group_source (tags por defecto)."""
        cached = self.cache.get(("groups",))
        if cached is not None:
            return list(cached)
        records = self.get_paginated(self.group_endpoint, {})
        # El walrus deja el filtro y el valor en un solo lookup, y hace explícito
        # que lo que entra al set ya pasó por el guard: con dos `.get()` separados
        # el tipo seguía siendo `Any | None` aunque en runtime nunca lo fuera.
        groups = sorted({slug for r in records if (slug := r.get("slug"))})
        self.cache.set(("groups",), groups)
        return list(groups)

    def resolve_device(self, device_name: str) -> dict[str, Any]:
        """Parámetros de conexión de un dispositivo, sin credenciales."""
        cached = self.cache.get(("device", device_name))
        if cached is not None:
            return dict(cached)

        records = self.query_devices(name=device_name)
        exact = [r for r in records if r.get("name") == device_name]
        if len(exact) != len(records):
            log.warning(
                f"Fedele: ?name={device_name} returned {len(records)} records and only "
                f"{len(exact)} carry that exact name. Falling back to the local check."
            )
        if not exact:
            raise InventoryError(
                f"Device '{device_name}' does not exist in Fedele, or falls outside the "
                f"configured scope ({self.scope or 'no filter'})."
            )
        if len(exact) > 1:
            raise InventoryError(
                f"Fedele returned {len(exact)} devices with the exact name "
                f"'{device_name}'. An ambiguous name is not resolved by elimination."
            )

        params, reason = self.to_params(exact[0])
        if params is None:
            raise InventoryError(
                f"Device '{device_name}' exists in Fedele but is not manageable "
                f"by Netmiko: {reason}"
                + (
                    f" (platform='{(exact[0].get('platform') or {}).get('name')}')"
                    if reason == EXCLUDED_PLATFORM_UNSUPPORTED
                    else ""
                )
            )
        self.cache.set(("device", device_name), dict(params))
        return params

    def devices_of(self, device_or_group: str) -> dict[str, dict[str, Any]]:
        """Dispositivos gestionables de un grupo, o de un único dispositivo.

        Se intenta primero como grupo; si no matchea ninguno, se prueba como
        nombre de dispositivo. Ese orden importa: 'all' y los nombres de grupo son
        lo que el LLM usa más seguido en comandos de grupo.
        """
        cached = self.cache.get(("expand", device_or_group))
        if cached is not None:
            self.last_excluded = dict(cached["excluded"])
            return {k: dict(v) for k, v in cached["devices"].items()}

        is_group = False
        if device_or_group == "all":
            records = self.query_devices()
        else:
            is_group = device_or_group in self.list_groups()
            if is_group:
                records = self.query_devices(**{self.group_param: device_or_group})
            else:
                records = [
                    r
                    for r in self.query_devices(name=device_or_group)
                    if r.get("name") == device_or_group
                ]
                if not records:
                    raise InventoryError(
                        f"'{device_or_group}' is neither a {settings.fedele_group_source} "
                        f"entry nor a device in Fedele, within the configured scope "
                        f"({self.scope or 'no filter'})."
                    )

        devices: dict[str, dict[str, Any]] = {}
        excluded: dict[str, str] = {}
        for record in records:
            device_name = record.get("name")
            if not device_name:
                continue
            params, reason = self.to_params(record)
            if params is None:
                excluded[device_name] = reason or "desconocido"
            else:
                devices[device_name] = params

        self.last_excluded = excluded

        if excluded:
            log.info(
                f"Fedele: '{device_or_group}' → {len(devices)} manageable devices, "
                f"{len(excluded)} excluded ({dict(Counter(excluded.values()))})."
            )

        if is_group and not devices:
            if excluded:
                raise InventoryError(
                    f"The {settings.fedele_group_source[:-1]} '{device_or_group}' groups "
                    f"{len(excluded)} devices, but none of them is manageable by Netmiko "
                    f"({dict(Counter(excluded.values()))})."
                )
            raise InventoryError(
                f"The {settings.fedele_group_source[:-1]} '{device_or_group}' exists in "
                f"Fedele but has no devices assigned"
                + (f" within the {self.scope} scope." if self.scope else ".")
            )

        self.cache.set(
            ("expand", device_or_group),
            {"devices": {k: dict(v) for k, v in devices.items()}, "excluded": dict(excluded)},
        )
        return devices

    def resolve_group(self, device_or_group: str) -> list[str]:
        return list(self.devices_of(device_or_group).keys())

    def all_devices(self, device_or_group: str) -> dict[str, dict[str, Any]]:
        return self.devices_of(device_or_group)

    def source_info(self) -> dict[str, Any]:
        """Procedencia del inventario, para netmiko.get_metadata."""
        info: dict[str, Any] = {
            "backend": self.name,
            "url": self.client.api_url,
            "available": self.client.available,
            "group_source": settings.fedele_group_source,
            "scope_filter": self.scope or None,
            "cache_ttl_seconds": settings.fedele_cache_ttl,
        }
        if not self.scope:
            info["warning"] = (
                "Without fedele_device_filter: the inventory covers the SoT's whole estate."
            )
        if not self.client.available:
            info["warning"] = "Fedele is not responding; the circuit breaker is open."
        return info


def build_inventory_backend() -> Any:
    """Devuelve el backend de inventario según inventory_type.

    La elección es explícita por configuración. Sin detección automática ni
    fallback silencioso: que un mismo nombre resuelva a direcciones distintas
    según qué servicio estuviera arriba es, sobre un equipo de red, la diferencia
    entre correr un show en la caja correcta y en la de otro.
    """
    if settings.inventory_backend == "fedele":
        return FedeleInventoryBackend()
    return YamlInventoryBackend()


class DeferredInventoryBackend:
    """Placeholder que relanza el error de construcción en cada uso.

    Mismo criterio que DeferredCredentialProvider: el módulo se importa igual y
    el problema se reporta por startup_error y por cada tool, en vez de matar el
    proceso al importar.
    """

    name = "unavailable"

    def __init__(self, error: Exception) -> None:
        self.error = error
        self.last_excluded: dict[str, str] = {}

    def fail(self) -> Any:
        raise InventoryError(str(self.error))

    def list_groups(self) -> list[str]:
        return self.fail()

    def resolve_device(self, device_name: str) -> dict[str, Any]:
        return self.fail()

    def resolve_group(self, device_or_group: str) -> list[str]:
        return self.fail()

    def all_devices(self, device_or_group: str) -> dict[str, dict[str, Any]]:
        return self.fail()

    def source_info(self) -> dict[str, Any]:
        return {"backend": self.name, "error": str(self.error)}


inventory_build_error: str | None = None
try:
    inventory_backend: Any = build_inventory_backend()
except Exception as exc:  # noqa: BLE001 — cualquier falla debe degradar, no matar
    inventory_build_error = f"Inventory backend ({settings.inventory_backend}): {exc}"
    inventory_backend = DeferredInventoryBackend(exc)

credential_build_error: str | None = None
try:
    credential_provider: Any = build_credential_provider()
except Exception as exc:  # noqa: BLE001
    credential_build_error = f"Credential provider ({settings.credential_source}): {exc}"
    credential_provider = DeferredCredentialProvider(exc)


def get_sanitized_inventory(device_or_group: str) -> dict[str, Any]:
    """Inventario de un dispositivo, grupo o 'all', sin datos sensibles.

    Es lo único del inventario que puede ver el LLM. Filtra explícitamente los
    campos de credencial aunque el backend ya no los devuelva — defensa en
    profundidad: si mañana un backend nuevo los incluye, esto no se entera pero
    igual los saca.
    """
    devices = inventory_backend.all_devices(device_or_group)
    return {
        name: {
            k: v
            for k, v in params.items()
            if k not in CREDENTIAL_FIELDS and k not in INTERNAL_FIELDS
        }
        for name, params in devices.items()
    }


def strip_internal_fields(params: dict[str, Any]) -> dict[str, Any]:
    """Saca los campos internos del backend antes de que el dict sea kwargs.

    Lo que sale de acá va a `ConnectHandler(**params)`, y Netmiko rechaza
    cualquier clave que no conozca: `BaseConnection.__init__() got an unexpected
    keyword argument 'fedele_id'`. El error aparece recién al conectar contra un
    equipo real, así que no lo ve ningún test que corte antes.

    Tiene que correr DESPUÉS de resolver las credenciales: el proveedor de Fedele
    necesita justamente `fedele_id` para pedirle el secreto al SoT.
    """
    return {k: v for k, v in params.items() if k not in INTERNAL_FIELDS}


def get_connection_data(device_name: str) -> dict[str, Any]:
    """Parámetros completos de conexión de un dispositivo. USO INTERNO.

    Es el punto donde convergen el inventario (§8) y las credenciales (§6), y el
    único lugar del archivo que arma el dict con secretos.

    NO exponer como tool: devolvería credenciales al contexto del LLM, y de ahí
    al transcript de la conversación y al historial. La variante visible para el
    usuario es netmiko.list_devices, que va por get_sanitized_inventory.
    """
    device = inventory_backend.resolve_device(device_name)
    credentials = credential_provider.get_credentials(device_name, device)
    return strip_internal_fields({**device, **credentials})


def get_all_connection_data(device_or_group: str) -> dict[str, dict[str, Any]]:
    """get_connection_data para todos los dispositivos de un grupo. USO INTERNO.

    Resuelve inventario y credenciales una sola vez antes de abrir los hilos.
    """
    devices = inventory_backend.all_devices(device_or_group)
    return {
        name: strip_internal_fields(
            {**params, **credential_provider.get_credentials(name, params)}
        )
        for name, params in devices.items()
    }


@contextmanager
def managed_connection(
    connect_params: dict[str, Any],
    *,
    device_name: str = "?",
    correlation_id: str = "-",
) -> Generator[BaseConnection, None, None]:
    """Maneja el ciclo de vida de la sesión SSH de una ejecución.

    Establece la conexión Netmiko y la cede al llamador. Las excepciones de la
    fase de conexión se propagan sin capturarse acá: las maneja run_show_command
    en sus except externos, donde están disponibles el correlation ID y el
    contexto de auditoría.

    En salida limpia se desconecta la sesión. Ante cualquier excepción del bloque
    del llamador también se desconecta y se relanza. Descartar en vez de reciclar
    es intencional: el estado del canal después de un comando fallido es
    indefinido, y un futuro pool de conexiones nunca debería recibir una conexión
    con el prompt sucio.

    Cuando se implemente pooling, esta función es el lugar correcto para cambiar
    cerrar-al-salir por devolver-al-pool, sin tocar run_show_command.

    device_name y correlation_id son solo para el log: acá es donde se sabe a qué
    dirección se sale y con qué ssh_config, y en ninguna otra parte. Sin esa línea
    un equipo alcanzable solo por jumphost falla con un TIMEOUT que no menciona el
    salto, y el diagnóstico natural —"falta VPN", "el equipo está caído"— es falso.
    """
    ssh_config: str | None = None
    if settings.ssh_config_file:
        ssh_config = str(Path(settings.ssh_config_file).expanduser())
        connect_params = {**connect_params, "ssh_config_file": ssh_config}

    ssh_config_field = f"'{ssh_config}'" if ssh_config else "none (direct TCP)"
    log.debug(
        f"Connecting to '{device_name}': host={connect_params.get('host')} "
        f"device_type={connect_params.get('device_type')} "
        f"ssh_config={ssh_config_field} correlation_id={correlation_id}"
    )
    started = time.monotonic()
    try:
        net_connect = ConnectHandler(**connect_params)
    except Exception as exc:
        log.warning(
            f"Connection to '{device_name}' failed after "
            f"{time.monotonic() - started:.1f}s: host={connect_params.get('host')} "
            f"error={type(exc).__name__}: {exc} correlation_id={correlation_id}"
        )
        raise
    log.debug(
        f"Session opened with '{device_name}' in {time.monotonic() - started:.1f}s "
        f"correlation_id={correlation_id}"
    )
    try:
        yield net_connect
    except Exception:
        net_connect.disconnect()
        log.debug(
            f"Session with '{device_name}' closed after an error "
            f"({time.monotonic() - started:.1f}s total) correlation_id={correlation_id}"
        )
        raise
    else:
        net_connect.disconnect()
        log.debug(
            f"Session with '{device_name}' closed cleanly "
            f"({time.monotonic() - started:.1f}s total) correlation_id={correlation_id}"
        )


def run_show_command(
    device_name: str,
    command: str,
    use_textfsm: bool = False,
    save_output: bool = False,
    *,
    tool_name: str = "netmiko.send_show_command",
    given_correlation_id: str | None = None,
    preloaded_params: dict[str, Any] | None = None,
    auto_save: bool = True,
) -> str | list[Any] | dict[str, Any]:
    """Conecta a un dispositivo y ejecuta un único show command.

    Devuelve la salida del comando (o datos estructurados si se parseó), o un
    string de error si falla la validación, la búsqueda en inventario, la
    resolución de credenciales o la conexión.

    Los parámetros keyword-only son internos. tool_name se registra en la
    auditoría para que los comandos de grupo queden atribuidos a la tool de
    grupo. Se genera un correlation_id nuevo por llamada si no se provee, lo que
    vincula los registros command_attempt y connection_outcome de una misma
    operación.
    """
    correlation_id = given_correlation_id or str(uuid.uuid4())
    audit_context = CommandAuditContext(
        correlation_id=correlation_id,
        tool=tool_name,
        device=device_name,
        command=command,
    )

    result: ValidationResult = validate_command(command)
    audit_context.log_attempt(ALLOWED if result.allowed else DENIED, result.reason)
    if not result.allowed:
        return f"Security Error: Command '{command}' is not permitted."

    try:
        params = (
            preloaded_params if preloaded_params is not None else get_connection_data(device_name)
        )
    except InventoryError as e:
        audit_context.log_outcome(OUTCOME_INVENTORY_ERROR, detail=str(e))
        return f"Inventory Error: {str(e)}"
    except CredentialError as e:
        audit_context.log_outcome(OUTCOME_CREDENTIAL_ERROR, detail=str(e))
        return f"Credential Error: {str(e)}"
    except FedeleError as e:
        audit_context.log_outcome(OUTCOME_SOT_ERROR, detail=str(e))
        return f"Fedele Error: {str(e)}"

    session_log_buf: io.BytesIO | None = None
    connect_params: dict[str, Any] = dict(params)
    if settings.audit_log_read_transcript:
        session_log_buf = io.BytesIO()
        connect_params["session_log"] = session_log_buf

    try:
        with managed_connection(
            connect_params, device_name=device_name, correlation_id=correlation_id
        ) as net_connect:
            try:
                output = net_connect.send_command(
                    result.normalized_command, use_textfsm=use_textfsm
                )

                textfsm_parse_failed = use_textfsm and isinstance(output, str)

                final_output: str | list[Any] | dict[str, Any]
                if isinstance(output, (list, dict)):
                    final_output = output
                else:
                    final_output = str(output)

            except ReadTimeout:
                audit_context.log_outcome(OUTCOME_READ_TIMEOUT)
                return (
                    f"Connection Error: Device '{device_name}' stopped responding "
                    f"while reading command output."
                )
            except ReadException as e:
                audit_context.log_outcome(OUTCOME_READ_ERROR, detail=str(e))
                return f"Connection Error: Failed to read output from '{device_name}': {str(e)}"
            except WriteException as e:
                audit_context.log_outcome(OUTCOME_WRITE_ERROR, detail=str(e))
                return f"Connection Error: Failed to send command to '{device_name}': {str(e)}"
            except NetmikoBaseException as e:
                audit_context.log_outcome(OUTCOME_NETMIKO_ERROR, detail=str(e))
                return f"Connection Error: {str(e)}"
            except Exception as e:  # noqa: BLE001 — el server no revienta por un error de ejecución: lo audita y lo devuelve
                audit_context.log_outcome(OUTCOME_ERROR, detail=traceback.format_exc())
                return f"Execution Error: An unexpected error occurred: {str(e)}"

            if save_output:
                saved_path_str = save_device_output(device_name, command, final_output)
                saved_filename = Path(saved_path_str).name
                final_output = f"Output saved as '{saved_filename}'."
            elif auto_save:
                as_str = (
                    json.dumps(final_output, indent=2)
                    if isinstance(final_output, (list, dict))
                    else str(final_output)
                )
                line_count = len(as_str.splitlines())
                if line_count > settings.save_threshold:
                    saved_path_str = save_device_output(device_name, command, final_output)
                    saved_filename = Path(saved_path_str).name
                    final_output = (
                        f"Output too large to return inline ({line_count:,} lines, "
                        f"exceeds save_threshold of {settings.save_threshold:,}). "
                        f"Automatically saved as '{saved_filename}'. "
                        f"Use netmiko.read_device_output to retrieve it."
                    )

            if session_log_buf is not None:
                save_channel_transcript(correlation_id, device_name, session_log_buf.getvalue())
            audit_context.log_outcome(OUTCOME_SUCCESS, textfsm_parse_failed=textfsm_parse_failed)
            return final_output

    except NetmikoAuthenticationException:
        audit_context.log_outcome(OUTCOME_AUTH_FAILURE)
        return f"Connection Error: Authentication failed for device '{device_name}'."
    except NetmikoTimeoutException:
        audit_context.log_outcome(OUTCOME_TIMEOUT)
        return f"Connection Error: Connection to device '{device_name}' timed out."
    except SSHException as e:
        audit_context.log_outcome(OUTCOME_SSH_ERROR, detail=str(e))
        return f"Connection Error: SSH protocol error for '{device_name}': {str(e)}"
    except NetmikoBaseException as e:
        audit_context.log_outcome(OUTCOME_NETMIKO_ERROR, detail=str(e))
        return f"Connection Error: {str(e)}"
    except Exception as e:  # noqa: BLE001 — el server no revienta por un error de ejecución: lo audita y lo devuelve
        audit_context.log_outcome(OUTCOME_ERROR, detail=traceback.format_exc())
        return f"Execution Error: An unexpected error occurred: {str(e)}"


UNSAFE_PATH_CHARS: list[str] = [
    "/",
    "\\",
    "..",
    "\x00",
    "∕",
    "／",
    "⁄",
    "⧸",
    "＼",
    "⧵",
    "∖",
    "⧹",
]

UNSAFE_PATH_VALUES: frozenset[str] = frozenset({"", "."})


def validate_path_component(value: str, label: str) -> None:
    """Lanza ValueError si value está en UNSAFE_PATH_VALUES o contiene alguna
    secuencia de UNSAFE_PATH_CHARS.

    Centraliza la validación de componentes de ruta para poder extender el
    conjunto de reglas en un solo lugar. label nombra el argumento que se está
    chequeando (p. ej. "device name" o "filename") para que el llamador reciba un
    error preciso.
    """
    if value in UNSAFE_PATH_VALUES:
        raise ValueError(f"Security Error: Unsafe path value (src: {label}, value: {value!r})")
    if any(unsafe in value for unsafe in UNSAFE_PATH_CHARS):
        raise ValueError(
            f"Security Error: Insecure characters detected in path (src: {label}, value: {value})"
        )


def sanitize_command_for_filename(command: str) -> str:
    """Convierte un comando en un componente de nombre de archivo seguro.

    Normaliza el whitespace y reemplaza los caracteres no alfanuméricos por
    guiones bajos. Se trunca a 50 caracteres para que los nombres sigan siendo
    manejables.
    """
    normalized = "_".join(command.split())
    safe = "".join(c if c.isalnum() or c == "_" else "_" for c in normalized)
    return safe[:50]


def save_device_output(device_name: str, command: str, output: Any) -> str:
    """Guarda la salida en un archivo por dispositivo y devuelve la ruta absoluta.

    Los directorios se crean con modo 0o700 (solo el dueño) para que otros
    usuarios del sistema no puedan leer salidas potencialmente sensibles.
    """
    validate_path_component(device_name, "device name")
    base_dir = Path(settings.save_output_dir).expanduser()
    base_dir.mkdir(parents=True, exist_ok=True)
    base_dir.chmod(0o700)

    device_dir = base_dir / device_name
    device_dir.mkdir(exist_ok=True)
    device_dir.chmod(0o700)

    cmd_name = sanitize_command_for_filename(command)
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    file_path = device_dir / f"{cmd_name}_{timestamp}.txt"
    content = json.dumps(output, indent=2) if isinstance(output, (list, dict)) else str(output)
    file_path.write_text(content, encoding="utf-8")
    file_path.chmod(0o600)
    return str(file_path)


def list_saved_outputs(device_or_group: str) -> dict[str, Any]:
    """Lista los archivos de salida guardados de un dispositivo, grupo o 'all'.

    Devuelve un dict que mapea cada dispositivo a su lista de archivos (más
    nuevos primero). Los dispositivos sin salidas guardadas aparecen con lista
    vacía.
    """
    try:
        device_names = inventory_backend.resolve_group(device_or_group)
    except InventoryError as e:
        return {"error": f"Inventory Error: {str(e)}"}
    except FedeleError as e:
        return {"error": f"Fedele Error: {str(e)}"}

    base_dir = Path(settings.save_output_dir).expanduser()
    result: dict[str, Any] = {}

    for device_name in device_names:
        device_dir = base_dir / device_name
        if not device_dir.is_dir():
            result[device_name] = []
        else:
            result[device_name] = sorted(
                [f.name for f in device_dir.glob("*.txt")],
                reverse=True,
            )

    return result


def read_saved_output(
    device_name: str,
    filename: str,
    offset: int = 0,
    limit: int = 500,
) -> str:
    """Lee con paginado un archivo de salida guardado de un dispositivo.

    device_name y filename se validan para prevenir path traversal.

    Devuelve una porción paginada del archivo con un encabezado que indica el
    rango de líneas y el total, más una pista de continuación cuando quedan
    líneas. Devuelve un string de error si falla la validación o no se encuentra
    el archivo.
    """
    try:
        validate_path_component(device_name, "device name")
        validate_path_component(filename, "filename")
    except ValueError as e:
        return str(e)

    base_dir = Path(settings.save_output_dir).expanduser()
    device_dir = base_dir / device_name
    file_path = device_dir / filename

    try:
        if not file_path.resolve().is_relative_to(base_dir.resolve()):
            return (
                f"Security Error: Path resolves outside restricted directory "
                f"(device: {device_name}, file: {filename})"
            )
    except Exception:  # noqa: BLE001 — cualquier falla resolviendo el path se trata como intento de escape  # pragma: no cover
        return (
            f"Security Error: Path resolves outside restricted directory "
            f"(device: {device_name}, file: {filename})"
        )

    if not device_dir.is_dir():
        return f"Error: No saved output found for device '{device_name}'."
    if not file_path.is_file():
        return f"Error: File '{filename}' not found for device '{device_name}'."

    content = file_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    total = len(lines)

    if total == 0:
        return "Lines 0-0 of 0.\n"

    if offset >= total:
        return (
            f"Error: offset {offset} is beyond end of file "
            f"({total} line{'s' if total != 1 else ''})."
        )

    end = min(offset + limit, total)
    page = lines[offset:end]

    display_start = offset + 1
    if end < total:
        continuation = f" Call netmiko.read_device_output with offset={end} to continue."
    else:
        continuation = ""

    header = f"Lines {display_start}-{end} of {total}.{continuation}"
    return header + "\n" + "\n".join(page)


def run_show_command_on_group(
    device_or_group: str,
    command: str,
    use_textfsm: bool = False,
    save_output: bool = False,
) -> dict[str, Any]:
    """Ejecuta un show command en un grupo de dispositivos, concurrentemente.

    El comando se valida una sola vez antes de abrir ninguna conexión. Si no está
    permitido, se emite un registro de auditoría de la denegación a nivel grupo y
    se devuelve el error de seguridad sin conectarse a ningún equipo.

    Los registros por dispositivo (command_attempt y connection_outcome) los
    emite run_show_command dentro de cada hilo.

    Devuelve un dict que mapea cada dispositivo a su salida (o al archivo donde
    se guardó).
    """
    result: ValidationResult = validate_command(command)
    if not result.allowed:
        correlation_id = str(uuid.uuid4())
        audit_context = CommandAuditContext(
            correlation_id=correlation_id,
            tool="netmiko.send_show_command_to_group",
            device=f"GROUP:{device_or_group}",
            command=command,
        )
        audit_context.log_attempt(DENIED, result.reason)
        return {"error": f"Security Error: Command '{command}' is not permitted."}

    try:
        all_device_params = get_all_connection_data(device_or_group)
    except InventoryError as e:
        return {"error": f"Inventory Error: {str(e)}"}
    except CredentialError as e:
        return {"error": f"Credential Error: {str(e)}"}
    except FedeleError as e:
        return {"error": f"Fedele Error: {str(e)}"}

    results: dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=settings.max_workers) as executor:
        future_to_device = {
            executor.submit(
                run_show_command,
                name,
                command,
                use_textfsm,
                False,
                tool_name="netmiko.send_show_command_to_group",
                preloaded_params=params,
                auto_save=not save_output,
            ): name
            for name, params in all_device_params.items()
        }
        for future in as_completed(future_to_device):
            device_name = future_to_device[future]
            try:
                output = future.result()
                if save_output:
                    saved_path_str = save_device_output(device_name, command, output)
                    saved_filename = Path(saved_path_str).name
                    results[device_name] = f"Output saved as '{saved_filename}'."
                else:
                    results[device_name] = output
            except Exception as e:  # noqa: BLE001 — una falla en un equipo no puede abortar el resto del grupo
                results[device_name] = f"Execution Error: {str(e)}"

    return results


try:
    from niko.srvclass_list_budget import apply_budget_to_payload
except ImportError:
    
    def apply_budget_to_payload(payload: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
        """No-op fuera de Niko: sin presupuesto de listas que aplicar."""
        return payload


# `version` e `instructions` viajan en el serverInfo del handshake `initialize`.
# Sin ellos la versión sólo se alcanza llamando a netmiko.get_metadata, que es
# una tool: para saber qué está corriendo hay que hablar con el server en vez de
# leer lo que ya declaró al conectarse.
mcp = FastMCP(
    name="mcp-netmiko",
    instructions="Read-only access to network devices over SSH via Netmiko.",
    version=__VERSION__,
)

NETMIKO_CORE_FIELDS: frozenset[str] = frozenset(
    {
        "device", "device_type", "host", "ip", "port", "name",
        "group", "groups", "site", "role", "platform", "tags",
        "status", "description",
    }
)

startup_error: str | None = None

startup_warning: str | None = None

ToolFunc = TypeVar("ToolFunc", bound=Callable[..., Any])


def json_result(payload: Any) -> str:
    """Serializa la respuesta de una tool aplicando el presupuesto de listas.

    Igual que entropy y fedele: la respuesta siempre declara lo que hizo. Un
    listado recortado que no lo dijera haría que el LLM afirme un total con toda
    confianza.
    """
    if isinstance(payload, dict):
        apply_budget_to_payload(
            payload,
            core_fields=NETMIKO_CORE_FIELDS,
            prefix="NETMIKO",
            detail_hint="netmiko.list_devices(device_or_group=<nombre>) para el detalle completo",
        )
    return json.dumps(payload, default=str)


def check_startup_error(func: ToolFunc) -> ToolFunc:  # noqa: UP047 — TypeVar y no PEP695: mantiene la forma de upstream en el decorador
    """Corta la tool y devuelve startup_error si el arranque falló.

    Se aplica debajo de @mcp.tool() en cada tool, para que un servidor mal
    configurado se manifieste con un error claro en cualquier llamada en vez de
    comportarse raro en silencio. functools.wraps preserva la metadata original
    para que FastMCP genere el esquema correcto.

    El wrapper es async porque todas las tools lo son: un wrapper sincrónico
    devolvería la corrutina sin await.
    """

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        if startup_error:
            return json_result({"success": False, "error": startup_error})
        return await func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


@mcp.tool(name="netmiko.get_metadata")
@check_startup_error
async def get_metadata() -> str:
    """
    Return authoritative metadata about the Netmiko MCP server and its inventory.

    MANDATORY — call this tool FIRST on EVERY user message that mentions, asks about,
    or relates to network devices, routers, switches, firewalls, show commands, device
    inventory or device groups, before any other netmiko tool and before answering
    from memory, system prompt, or RAG/FAQ.

    It reports which inventory backend is active (Fedele or the local YAML file) and,
    for the local file, how old it is. That matters: operating from a stale local
    inventory can send a command to the wrong box.

    This tool does NOT reach any network device. For "is the MCP alive" call
    netmiko.health_check. To actually query a device, use netmiko.send_show_command.

    Returns:
        str: JSON with `version`, `author`, `description`, `inventory`, `capabilities`,
             `command_policy` and `tool_routing`. `command_policy` is "file" when the
             operator's allow/deny list is in force and "fallback" when no policy file
             exists — in that case a `warning` field says so, only a handful of
             read-only commands will be accepted, and you must relay that warning to
             the user instead of treating the denials as device failures.
    """
    description = """
        Netmiko MCP provides read-only access to network devices (routers, switches,
        firewalls) over SSH. Every command is checked against an operator-defined
        allow/deny list before execution, and every attempt is written to a
        fail-closed audit trail. There is no configuration tool: this server cannot
        change device state, only read it.
    """

    device_types: list[str] = []
    try:
        device_types = sorted(
            {d.get("device_type") for d in inventory_backend.all_devices("all").values() if d.get("device_type")}
        )
    except Exception as exc:  # noqa: BLE001 — informativo, nunca bloqueante
        log.debug(f"get_metadata: could not enumerate device_types ({exc})")

    metadata = {
        "version": __VERSION__,
        "author": "Ed Scrimaglia / Kirk Byers",
        "description": description.strip(),
        "inventory": inventory_backend.source_info(),
        "credential_source": settings.credential_source,
        "device_types_in_inventory": device_types,
        "command_syntax_warning": (
            "CADA PLATAFORMA TIENE SU PROPIA CLI. Netmiko soporta 177 device_types base "
            "(416 con variantes) de 102 fabricantes, y sus sintaxis NO son intercambiables. "
            "'show version' no existe en Huawei VRP (es 'display version'), ni en MikroTik "
            "RouterOS (es '/system resource print'), ni en F5 tmsh. Antes de componer un "
            "comando, mirar el device_type del equipo con netmiko.list_devices y usar la "
            "sintaxis de ESA plataforma. No traducir un comando de una familia a otra por "
            "analogía, y no reintentar con variantes a ver cuál entra."
        ),
        "capabilities": {
            "read_only": True,
            "config_changes": False,
            "textfsm_parsing": True,
            "pipe_modifiers": settings.allow_pipe,
        },
        "command_policy": command_policy_source(),
        "tool_routing": {
            "netmiko.send_show_command": (
                "Un solo dispositivo, por nombre de inventario. Usar cuando el usuario "
                "nombra un equipo concreto."
            ),
            "netmiko.send_show_command_to_group": (
                "Varios dispositivos en paralelo. Usar cuando el usuario nombra un grupo "
                "o pide el mismo comando 'en todos'."
            ),
            "netmiko.health_check": (
                "¿Responde el servidor MCP? No toca ningún equipo de red y no dice nada "
                "sobre el estado de un dispositivo."
            ),
            "netmiko.list_devices": (
                "Qué equipos existen y sus datos NO sensibles. Nunca devuelve credenciales."
            ),
            "netmiko.read_device_output": (
                "Recupera una salida que se guardó a disco por superar save_threshold."
            ),
            "netmiko.get_command_policy": (
                "Qué comandos acepta este servidor y de dónde sale esa política. "
                "Llamarla DESPUÉS de una denegación y ANTES de reintentar: es la "
                "alternativa a tantear variantes, que está prohibido."
            ),
        },
    }
    if startup_warning:
        metadata["warning"] = startup_warning
    log.debug("Netmiko MCP metadata returned.")
    return json_result(metadata)


@mcp.tool(name="netmiko.get_command_policy")
@check_startup_error
async def get_command_policy() -> str:
    """
    List the commands this server will accept, and where that policy comes from.

    CALL THIS AFTER A REFUSAL, BEFORE RETRYING. A `Security Error: Command ... is not
    permitted` means the command is outside the operator's policy. Do not guess a
    variant and do not abbreviate — read the policy here, pick a command that is
    actually allowed, and if nothing fits, tell the user which command was refused
    and what the allow list does cover.

    Also useful when the user asks what they can run on this deployment.

    ANSWERING "which commands are available for Juniper / Huawei / Cisco": the lists
    are flat, because the operator writes one policy for the whole estate. Filter it
    yourself by dialect — you know the CLIs, and `device_types_in_inventory` tells
    you which platforms are actually present. `show route*` and `show chassis*` are
    Junos, `display *` is Huawei VRP and HPE Comware, `show ip route` is Cisco-style,
    and `show version` happens to work on several. Under the fallback,
    `allowed_commands_by_platform` already carries that split, verbatim and exact —
    use it as given instead of re-deriving it. Two rules when you answer:
      - Never list a command that is not in `allowed_commands`. It will be refused.
      - Say when the answer is empty: an allow list written for one vendor covers
        nothing on another, and that is the operator's doing, not a device fault.

    `policy_source` says who wrote the policy in force:
      - "file"     — the operator's allow/deny list, at `command_file`.
      - "fallback" — no policy file exists on this deployment, so only a small
                     built-in read-only set runs. `warning` explains it; relay that
                     to the user, because every other refusal follows from it and
                     looks like a device problem otherwise.

    How the lists are read (getting this wrong wastes attempts, and every attempt is
    audited):
      - Deny wins over allow, always.
      - The allow list does NOT cover abbreviations: `show version` does not permit
        `sh ver`. Send full commands.
      - The deny list DOES cover abbreviations of the same word count: a deny on
        `configure` also blocks `conf`.
      - `*` is a glob and only ever appears at the end. `cmd*` swallows whatever
        follows; `cmd *` requires at least one more word and does not match `cmd`
        on its own.
      - Anything the allow list does not name is denied.

    Returns:
        str: JSON with `policy_source`, `command_file`, `allowed_commands`,
             `denied_commands`, their counts, a `rules` object,
             `device_types_in_inventory`, and — only under the fallback —
             `allowed_commands_by_platform` and a `warning`.
    """
    log_tool_invocation(tool="netmiko.get_command_policy", arguments={})
    commands = load_commands()
    allowed_commands = list(commands.get("allowed_commands", DEFAULT_ALLOWED_COMMANDS))
    denied_commands = list(commands.get("denied_commands", DEFAULT_DENIED_COMMANDS))

    payload: dict[str, Any] = {
        "success": True,
        "policy_source": command_policy_source(),
        "command_file": settings.command_file,
        "allowed_commands": allowed_commands,
        "denied_commands": denied_commands,
        "allowed_count": len(allowed_commands),
        "denied_count": len(denied_commands),
        "rules": {
            "deny_wins": True,
            "allow_covers_abbreviations": False,
            "deny_covers_abbreviations": True,
            "unlisted_commands_are_denied": True,
            "pipe_enabled": settings.allow_pipe,
            "pipe_modifiers": list(settings.pipe_modifiers) if settings.allow_pipe else [],
        },
    }
    if command_policy_source() == POLICY_SOURCE_FALLBACK:
        payload["allowed_commands_by_platform"] = {
            platform: list(cmds) for platform, cmds in FALLBACK_COMMANDS_BY_PLATFORM.items()
        }

    device_types: list[str] = []
    try:
        device_types = sorted(
            {
                d.get("device_type")
                for d in inventory_backend.all_devices("all").values()
                if d.get("device_type")
            }
        )
    except Exception as exc:  # noqa: BLE001 — informativo, nunca bloqueante
        log.debug(f"get_command_policy: could not enumerate device_types ({exc})")
    payload["device_types_in_inventory"] = device_types

    if startup_warning:
        payload["warning"] = startup_warning
    log.debug(
        f"Command policy returned: source={payload['policy_source']} "
        f"allowed={payload['allowed_count']} denied={payload['denied_count']}"
    )
    return json_result(payload)


@mcp.tool(name="netmiko.health_check")
@check_startup_error
async def health_check() -> str:
    """
    Check whether the Netmiko MCP server itself is responsive and correctly configured.

    IMPORTANT: If the user message involves network devices, call netmiko.get_metadata
    FIRST.

    This checks the MCP server, NOT any network device and NOT the inventory backend
    reachability. "¿Está arriba el router X?" is not this tool — that requires actually
    running a command against the device with netmiko.send_show_command.

    Returns:
        str: JSON with `available`, `version`, `inventory_backend`,
             `credential_source` and `command_policy` ("file" or "fallback").
             When `command_policy` is "fallback" a `warning` field explains that
             no policy file exists and only built-in read-only commands run;
             report that warning to the user.
    """
    log_tool_invocation(tool="netmiko.health_check", arguments={})
    payload: dict[str, Any] = {
        "success": True,
        "available": True,
        "server": mcp.name,
        "version": __VERSION__,
        "inventory_backend": settings.inventory_backend,
        "credential_source": settings.credential_source,
        "command_policy": command_policy_source(),
    }
    if startup_warning:
        payload["warning"] = startup_warning
    return json_result(payload)


@mcp.tool(name="netmiko.list_groups")
@check_startup_error
async def list_groups() -> str:
    """
    List every device group defined in the inventory.

    IMPORTANT: If the user message involves network devices, call netmiko.get_metadata
    FIRST.

    Groups are what netmiko.send_show_command_to_group accepts. Call this before
    assuming a group name exists — never invent one.

    Returns:
        str: JSON with `groups` (list of group-name strings) and `count`.
    """
    log_tool_invocation(tool="netmiko.list_groups", arguments={})
    try:
        groups = await asyncio.to_thread(inventory_backend.list_groups)
    except InventoryError as e:
        log.error(f"list_groups failed: {e}")
        return json_result({"success": False, "error": f"Inventory Error: {str(e)}"})
    except FedeleError as e:
        log.error(f"list_groups failed against Fedele: {e}")
        return json_result({"success": False, "error": f"Fedele Error: {str(e)}"})
    return json_result({"success": True, "groups": groups, "count": len(groups)})


@mcp.tool(name="netmiko.list_devices")
@check_startup_error
async def list_devices(device_or_group: str = "all") -> str:
    """
    List devices from the inventory, without credentials.

    IMPORTANT: If the user message involves network devices, call netmiko.get_metadata
    FIRST.

    Use this to discover exact device names before running a command. Device names are
    the only handle the other tools accept — never pass an IP address or a hostname you
    inferred.

    Args:
        device_or_group (str): 'all' (default), a group name, or a device name.

    Returns:
        str: JSON with `devices` (mapping of name to its non-sensitive parameters)
             and `count`. Credentials are never included.
    """
    log_tool_invocation(tool="netmiko.list_devices", arguments={"device_or_group": device_or_group})
    try:
        devices = await asyncio.to_thread(get_sanitized_inventory, device_or_group)
    except InventoryError as e:
        log.error(f"list_devices failed for '{device_or_group}': {e}")
        return json_result({"success": False, "error": f"Inventory Error: {str(e)}"})
    except FedeleError as e:
        log.error(f"list_devices failed against Fedele for '{device_or_group}': {e}")
        return json_result({"success": False, "error": f"Fedele Error: {str(e)}"})
    excluded = getattr(inventory_backend, "last_excluded", {}) or {}
    payload: dict[str, Any] = {"success": True, "devices": devices, "count": len(devices)}
    if excluded:
        payload["excluded_count"] = len(excluded)
        payload["excluded_reasons"] = dict(Counter(excluded.values()))
        payload["note"] = (
            "The excluded devices exist in the inventory but are not manageable "
            "over SSH with Netmiko. This is not the SoT's full device list."
        )
    return json_result(payload)


@mcp.tool(name="netmiko.send_show_command")
@check_startup_error
async def send_show_command(
    device_name: str,
    command: str,
    use_textfsm: bool = False,
    save_output: bool = False,
) -> str:
    """
    Connect to one network device over SSH and run a single show command.

    IMPORTANT: If the user message involves network devices, call netmiko.get_metadata
    FIRST.

    The command is validated against the operator's allow/deny list before execution.
    A rejection is NOT a bug and NOT something to work around: report it to the user
    and say which command was refused. Do not retry with an abbreviation — abbreviations
    are covered by the deny list, not by the allow list.

    SYNTAX IS PER-PLATFORM. Netmiko drives 177 base device_types (416 with variants)
    from 102 vendors and their CLIs are NOT interchangeable. Check the device's
    `device_type` with netmiko.list_devices first and use that platform's syntax:
    Cisco IOS/Arista/Juniper use `show ...`, Huawei VRP and HPE Comware use
    `display ...`, MikroTik RouterOS uses `/system resource print`, F5 tmsh uses
    `list`/`show` with its own grammar. Never translate a command from one family
    to another by analogy, and never probe variants to see which one is accepted —
    each attempt is audited and may be denied for a different reason.

    Args:
        device_name (str): Exact device name from the inventory (netmiko.list_devices).
        command (str): Full, un-abbreviated CLI command, e.g. 'show ip interface brief'.
        use_textfsm (bool): Parse the output into structured JSON via ntc-templates.
                            Falls back to raw text when no template exists.
        save_output (bool): Always write the output to disk and return the filename
                            instead of the content. Useful when you will refer back to
                            it several times.

    If save_output is False and the output exceeds save_threshold lines, it is saved
    automatically and a notice is returned instead. Retrieve it with
    netmiko.list_device_outputs and netmiko.read_device_output.

    Returns:
        str: JSON with `device`, `command`, and `output` on success; `error` on failure.
    """
    log.debug(f"send_show_command device={device_name!r} command={command!r}")
    output = await asyncio.to_thread(
        run_show_command,
        device_name,
        command,
        use_textfsm,
        save_output,
    )
    if isinstance(output, str) and output.startswith(
        ("Security Error:", "Inventory Error:", "Credential Error:", "Connection Error:", "Execution Error:")
    ):
        log.error(f"send_show_command failed on '{device_name}': {output}")
        return json_result({"success": False, "device": device_name, "error": output})
    return json_result(
        {"success": True, "device": device_name, "command": command, "output": output}
    )


@mcp.tool(name="netmiko.send_show_command_to_group")
@check_startup_error
async def send_show_command_to_group(
    device_or_group: str,
    command: str,
    use_textfsm: bool = False,
    save_output: bool = False,
) -> str:
    """
    Run the same show command concurrently on every device of a group.

    IMPORTANT: If the user message involves network devices, call netmiko.get_metadata
    FIRST.

    The command is validated once before any connection is opened, so a denied command
    reaches no device at all. Per-device failures are returned per device: a partial
    result is normal and must be reported as partial, never summarised as if every
    device answered.

    A GROUP MAY MIX PLATFORMS. The same command string is sent to every member, so a
    group holding both Cisco IOS and Huawei VRP devices will fail on half of them
    whatever you send — `show version` is invalid on VRP, `display version` is invalid
    on IOS. Check `device_type` across the group with netmiko.list_devices first; if
    the group is heterogeneous, issue one netmiko.send_show_command per platform
    instead of forcing a single string onto all of them.

    Args:
        device_or_group (str): Group name (netmiko.list_groups) or a single device name.
        command (str): Full, un-abbreviated CLI command.
        use_textfsm (bool): Parse each output into structured JSON where possible.
        save_output (bool): Save per-device output to disk and return filenames.

    Returns:
        str: JSON with `results` (mapping of device name to its output or error) and
             `count`.
    """
    log.debug(f"send_show_command_to_group target={device_or_group!r} command={command!r}")
    results = await asyncio.to_thread(
        run_show_command_on_group,
        device_or_group,
        command,
        use_textfsm,
        save_output,
    )
    if "error" in results and len(results) == 1:
        log.error(f"send_show_command_to_group failed on '{device_or_group}': {results['error']}")
        return json_result({"success": False, "target": device_or_group, "error": results["error"]})
    return json_result(
        {
            "success": True,
            "target": device_or_group,
            "command": command,
            "results": results,
            "count": len(results),
        }
    )


@mcp.tool(name="netmiko.list_device_outputs")
@check_startup_error
async def list_device_outputs(device_or_group: str) -> str:
    """
    List the output files already saved on disk for a device, group, or all devices.

    IMPORTANT: If the user message involves network devices, call netmiko.get_metadata
    FIRST.

    Outputs land here when save_output=True was used or when a command exceeded
    save_threshold. Read them with netmiko.read_device_output.

    Args:
        device_or_group (str): A device name, a group name, or 'all'.

    Returns:
        str: JSON with `outputs` (mapping of device name to its filenames, newest
             first). Devices with nothing saved appear with an empty list.
    """
    log_tool_invocation(
        tool="netmiko.list_device_outputs", arguments={"device_or_group": device_or_group}
    )
    outputs = await asyncio.to_thread(list_saved_outputs, device_or_group)
    if "error" in outputs:
        return json_result({"success": False, "error": outputs["error"]})
    return json_result({"success": True, "outputs": outputs})


@mcp.tool(name="netmiko.read_device_output")
@check_startup_error
async def read_device_output(
    device_name: str,
    filename: str,
    offset: int = 0,
    limit: int = 500,
) -> str:
    """
    Read a previously saved output file for one device, with pagination.

    IMPORTANT: If the user message involves network devices, call netmiko.get_metadata
    FIRST.

    The response header states the line range and the total line count. When lines
    remain, a continuation hint gives the offset to use next. Do not report a total
    based on a page you have not finished reading.

    Args:
        device_name (str): Device whose output directory to read from.
        filename (str): Exact filename as returned by netmiko.list_device_outputs.
        offset (int): 0-indexed line to start from. Defaults to 0.
        limit (int): Maximum lines per call. Defaults to 500.

    Returns:
        str: JSON with `device`, `filename` and `content` (the paginated slice).
    """
    log_tool_invocation(
        tool="netmiko.read_device_output",
        arguments={
            "device_name": device_name,
            "filename": filename,
            "offset": offset,
            "limit": limit,
        },
    )
    content = await asyncio.to_thread(read_saved_output, device_name, filename, offset, limit)
    if content.startswith(("Security Error:", "Error:")):
        return json_result({"success": False, "device": device_name, "error": content})
    return json_result(
        {"success": True, "device": device_name, "filename": filename, "content": content}
    )


@mcp.tool(name=AUDIT_QUERY_TOOL_NAME)
@check_startup_error
async def query_audit_trail(
    event: str = "",
    device: str = "",
    tool: str = "",
    command_contains: str = "",
    verdict: str = "",
    reason: str = "",
    outcome: str = "",
    correlation_id: str = "",
    since: str = "",
    until: str = "",
    order: str = "desc",
    limit: int = 50,
    summary_by: str = "",
    include_audit_queries: bool = False,
) -> str:
    """
    Read the audit trail: what this server was asked to do, and what happened.

    Answers questions about PAST activity — "everything done on SW-CORE-01",
    "the last 6 netmiko actions", "which commands were refused this week", "who
    touched that switch and with which credential". It reads the audit records
    only; it never opens a connection and never returns device output.

    Every argument is a filter, combined with AND. Leave one empty to not filter
    on it. Translate what the user asked into these arguments — do not ask for
    everything and sift through it.

    The audit trail rotates daily and this reads the rotated files too, but only
    what is still on disk. `files_scanned` and `oldest_available` in the response
    say how far back the answer actually reaches: if the period the user asked
    about is older than that, say so instead of reporting "nothing happened".

    `matched` is how many records satisfied the filters; `returned` is how many
    came back in this call. When they differ, the response is one page — never
    report `returned` as a total.

    Calling this tool writes a `tool_invocation` record of its own — reading the
    trail is itself auditable — but those records are hidden from the results by
    default, so "the last 6 actions" is about the network and not about your own
    questions. `audit_queries_hidden` says how many were left out.

    Args:
        event (str): Record type. One of command_attempt (a command was validated),
            connection_outcome (an SSH attempt finished), tool_invocation (a tool
            that touches no device was called), credential_resolution (which
            credential was used).
        device (str): Exact inventory device name, as netmiko.list_devices returns it.
        tool (str): Full tool name, e.g. 'netmiko.send_show_command'.
        command_contains (str): Case-insensitive substring of the command, e.g. 'running-config'.
        verdict (str): ALLOWED or DENIED. Only command_attempt records carry it.
        reason (str): Why a command was allowed or refused, e.g. DENY_MATCH, NO_ALLOW_MATCH.
        outcome (str): How an execution ended, e.g. SUCCESS, AUTH_FAILURE, TIMEOUT.
            Only connection_outcome records carry it.
        correlation_id (str): Ties the validation, the credential and the outcome of
            one single attempt together. Use it to reconstruct what happened in one case.
        since (str): ISO 8601 date or datetime, UTC. '2026-08-17' means from midnight.
        until (str): ISO 8601 date or datetime, UTC.
        order (str): 'desc' (newest first, the default) or 'asc'.
        limit (int): Maximum records to return. Defaults to 50, capped at 500.
        summary_by (str): Return counts instead of records, grouped by one of
            device, tool, outcome, verdict, event, day. Counts are exact over every
            matching record, not over one page. Use it for "how many" questions so
            a count does not cost hundreds of records. Combine it with an `event`
            filter to avoid a large '(absent)' bucket: records of one type do not
            carry the fields of another.
        include_audit_queries (bool): Include this tool's own invocations. Defaults
            to False. Set it to True only when the question is about who read the
            audit trail.

    Returns:
        str: JSON with `records` (or `summary`), plus `returned`, `matched`,
            `truncated`, `files_scanned`, `oldest_available` and `malformed_lines`.
    """
    log_tool_invocation(
        tool=AUDIT_QUERY_TOOL_NAME,
        arguments={
            "event": event,
            "device": device,
            "tool": tool,
            "command_contains": command_contains,
            "verdict": verdict,
            "reason": reason,
            "outcome": outcome,
            "correlation_id": correlation_id,
            "since": since,
            "until": until,
            "order": order,
            "limit": limit,
            "summary_by": summary_by,
            "include_audit_queries": include_audit_queries,
        },
    )

    # Both of these would otherwise answer with an empty list, which reads as
    # "nothing happened" when the truth is "there is nothing here to read".
    if not settings.audit_log_enabled:
        return json_result(
            {
                "success": False,
                "error": (
                    "Auditing is disabled (NETMIKO_MCP_AUDIT_LOG_ENABLED=false), so there "
                    "is no audit trail to query. Nothing has been recorded."
                ),
            }
        )
    if settings.audit_log_destination == AUDIT_DESTINATION_SYSLOG:
        return json_result(
            {
                "success": False,
                "error": (
                    "The audit trail goes to syslog only "
                    "(NETMIKO_MCP_AUDIT_LOG_DESTINATION=syslog), so there is no local file "
                    "to query. Query it on the syslog collector, or set the destination to "
                    "'both' to keep a local copy."
                ),
            }
        )

    try:
        payload = await asyncio.to_thread(
            run_audit_query,
            event=event,
            device=device,
            tool=tool,
            command_contains=command_contains,
            verdict=verdict,
            reason=reason,
            outcome=outcome,
            correlation_id=correlation_id,
            since=since,
            until=until,
            order=order,
            limit=limit,
            summary_by=summary_by,
            include_audit_queries=include_audit_queries,
        )
    except AuditQueryError as exc:
        log.warning(f"query_audit_trail rejected the query: {exc}")
        return json_result({"success": False, "error": f"Audit Query Error: {exc}"})
    except Exception as exc:  # noqa: BLE001 — la tool informa, no tumba el server
        log.error(f"query_audit_trail failed: {exc}")
        return json_result({"success": False, "error": f"Error reading the audit trail: {exc}"})

    log.debug(
        f"query_audit_trail: matched={payload['matched']} "
        f"returned={payload.get('returned', 0)} files={len(payload['files_scanned'])}"
    )
    return json_result(payload)


def validate_startup() -> str | None:
    """Valida la configuración requerida antes de atender pedidos.

    Devuelve un string de error, que se guarda en startup_error y reportan todas
    las tools, o None si está todo bien.

    A diferencia de upstream, acá NO se levanta SystemExit: Niko arranca este
    archivo como subprocess y sondea el puerto durante 30 segundos. Un proceso
    que muere al importar se ve, del lado de Niko, exactamente igual que un
    servidor que nunca arrancó — sin ninguna pista del motivo.
    """
    config_path_str = os.environ.get("NETMIKO_MCP_CONFIG")
    if config_path_str:
        config_path = Path(config_path_str).expanduser()
        if not config_path.is_file():
            return (
                f"Startup Error: NETMIKO_MCP_CONFIG is set to '{config_path_str}' "
                f"but that file does not exist."
            )

    if settings.inventory_backend == "yaml":
        if settings.inventory_file:
            inventory_path = Path(settings.inventory_file).expanduser()
            if not inventory_path.is_file():
                return (
                    f"Startup Error: inventory_file '{settings.inventory_file}' does not exist. "
                    f"Set NETMIKO_MCP_INVENTORY_FILE to a valid netmiko_tools inventory."
                )
    else:
        missing = [var for var in ("FEDELE_URL", "FEDELE_TOKEN") if not os.getenv(var)]
        if missing:
            return (
                f"Startup Error: inventory_type=fedele requires {', '.join(missing)} "
                f"in the environment."
            )

    if settings.ssh_config_file:
        ssh_config_path = Path(settings.ssh_config_file).expanduser()
        if not ssh_config_path.is_file():
            return (
                f"Startup Error: ssh_config_file '{settings.ssh_config_file}' does not exist. "
                f"Unset NETMIKO_MCP_SSH_CONFIG_FILE or point it at a valid OpenSSH config."
            )

    if inventory_build_error:
        return f"Startup Error: {inventory_build_error}"
    if credential_build_error:
        return f"Startup Error: {credential_build_error}"

    load_commands.cache_clear()
    try:
        commands = load_commands()
    except Exception as exc:  # noqa: BLE001 — el motivo llega al operador como Startup Error, no como traceback
        return (
            f"Startup Error: command_file '{settings.command_file}' could not be read: {exc}. "
            f"Fix the file, or remove it to fall back to the built-in read-only commands."
        )

    allowed_commands = commands.get("allowed_commands", DEFAULT_ALLOWED_COMMANDS)
    denied_commands = commands.get("denied_commands", DEFAULT_DENIED_COMMANDS)
    errors = validate_command_lists(
        allowed_commands=allowed_commands,
        denied_commands=denied_commands,
    )
    if errors:
        return "Startup Error: " + " ".join(errors)

    return None


def log_effective_config() -> None:
    """Deja escrito con qué configuración arrancó ESTE proceso.

    Un MCP lee su entorno, su bloque `env` y sus archivos de config una sola vez,
    al importar. A partir de ahí "lo que está corriendo" y "lo que dice el
    mcp_config.json de hoy" pueden diferir sin que nada lo señale, y todo
    diagnóstico arranca por esa pregunta. Sale a INFO —no a DEBUG— justamente
    porque en Niko el LOG_LEVEL habitual es INFO.

    No se escribe ningún secreto: ni FEDELE_TOKEN, ni la clave Fernet, ni las
    credenciales de los equipos. De la clave se registra si está o no, que es el
    dato operativo; el valor no agrega nada que no sea riesgo.
    """
    log.info(f"Config: Netmiko MCP {__VERSION__} starting")

    if settings.inventory_backend == "fedele":
        log.info(
            f"Config: inventory backend=fedele "
            f"url='{os.getenv('FEDELE_URL') or 'NOT SET'}' "
            f"group_source={settings.fedele_group_source} "
            f"scope_filter={settings.fedele_device_filter or 'none (the whole estate)'} "
            f"cache_ttl={settings.fedele_cache_ttl}s"
        )
    else:
        log.info(
            f"Config: inventory backend=yaml "
            f"file='{settings.inventory_file or 'NOT SET'}'"
        )

    credentials = f"Config: credential_source={settings.credential_source}"
    if settings.credential_source == "fedele":
        present = "present" if (os.getenv("FEDELE_CREDENTIALS_KEY") or "").strip() else "MISSING"
        credentials += f" FEDELE_CREDENTIALS_KEY={present}"
    log.info(credentials)

    try:
        policy = load_commands()
        policy_source = command_policy_source()
        allowed_count = len(policy.get("allowed_commands", DEFAULT_ALLOWED_COMMANDS))
        denied_count = len(policy.get("denied_commands", DEFAULT_DENIED_COMMANDS))
        policy_detail = (
            f"policy_source={policy_source} allowed={allowed_count} denied={denied_count}"
        )
    except Exception as exc:  # noqa: BLE001 — el arranque ya reportó el motivo
        policy_detail = f"policy_source=UNREADABLE ({exc})"

    log.info(
        f"Config: command_file='{settings.command_file}' {policy_detail} "
        f"allow_pipe={settings.allow_pipe} "
        f"save_output_dir='{settings.save_output_dir}' "
        f"save_threshold={settings.save_threshold} "
        f"max_workers={settings.max_workers}"
    )

    log.info(
        "Config: ssh_config="
        + (
            f"'{settings.ssh_config_file}'"
            if settings.ssh_config_file
            else "none — Netmiko does not read ~/.ssh/config on its own, so a device "
            "reachable only through a jumphost will fail with a timeout that never "
            "names the hop"
        )
    )

    log.info(
        f"Config: audit enabled={settings.audit_log_enabled} "
        f"destination={settings.audit_log_destination} "
        f"file='{settings.audit_log_file}' "
        f"transcript={settings.audit_log_read_transcript}"
    )


try:
    configure_audit_logger()
    startup_error = validate_startup()
except Exception as exc:  # noqa: BLE001 — la §11 nunca muere al importar: eso se ve igual que no haber arrancado
    startup_error = f"Startup Error: could not configure auditing: {exc}"

if not startup_error:
    try:
        startup_warning = command_policy_warning()
    except Exception as exc:  # noqa: BLE001 — la §11 nunca muere al importar: eso se ve igual que no haber arrancado  # pragma: no cover — depende del entorno
        startup_warning = None
        log.warning(f"Could not determine the command policy source: {exc}")

try:
    log_effective_config()
except Exception as exc:  # noqa: BLE001 — un log no puede tumbar el arranque  # pragma: no cover — un log no puede tumbar el arranque
    log.warning(f"Could not log the effective configuration: {exc}")

if startup_error:
    log.error(startup_error)
else:
    if startup_warning:
        log.warning(startup_warning)
    log.info(
        f"Netmiko MCP {__VERSION__} ready — inventory={settings.inventory_backend}, "
        f"credentials={settings.credential_source}, "
        f"command policy={command_policy_source()}"
    )


if __name__ == "__main__":
    log.info(f"--> Starting {mcp.name} MCP Server")
    log.debug(f"MCP server '{mcp.name}' started with transport 'stdio'")
    mcp.run(transport="stdio", show_banner=False)
