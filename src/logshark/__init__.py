"""LogShark — failed login and access detection for host and network logs."""

__version__ = "0.1.0"

from logshark.core import (
    ADAPTERS,
    AnalysisOptions,
    AnalysisResult,
    AdapterConfig,
    CustomAdapter,
    FirewallAdapter,
    JsonAdapter,
    LinuxAuthAdapter,
    SyslogAdapter,
    Windows4625Adapter,
    analyze_log,
    create_adapter,
    detect_format,
    extract_ip,
    normalize_ip,
)

__all__ = [
    "__version__",
    "ADAPTERS",
    "AdapterConfig",
    "AnalysisOptions",
    "AnalysisResult",
    "CustomAdapter",
    "FirewallAdapter",
    "JsonAdapter",
    "LinuxAuthAdapter",
    "SyslogAdapter",
    "Windows4625Adapter",
    "analyze_log",
    "create_adapter",
    "detect_format",
    "extract_ip",
    "normalize_ip",
]
