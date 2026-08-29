from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Any, Optional
import platform
import socket
import ssl
import subprocess
import sys
import psutil


@dataclass
class Vulnerability:
    severity: str
    title: str
    description: str
    remediation: str
    category: str
    affected_component: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None


@dataclass
class ScanResult:
    timestamp: datetime
    hostname: str
    os_info: Dict[str, str]
    vulnerabilities: List[Vulnerability]
    system_health: Dict[str, Any]
    scan_duration: float
    total_vulnerabilities: int
    severity_breakdown: Dict[str, int]
    recommendations: List[str]


class SecurityScanner:
    """
    Реальные, но лёгкие проверки, не требующие root/admin прав
    и не зависящие от внешних сетевых сканеров.
    Каждая проверка изолирована try/except, чтобы падение одной
    не останавливало весь скан.
    """

    MIN_SAFE_PYTHON = (3, 11)
    MIN_SAFE_OPENSSL = (3, 0, 8)

    def __init__(self):
        self.results: List[Vulnerability] = []

    def run_full_scan(self) -> ScanResult:
        start_time = datetime.now()

        vulnerabilities: List[Vulnerability] = []
        vulnerabilities += self._check_python_version()
        vulnerabilities += self._check_openssl_version()
        vulnerabilities += self._check_open_ssh_port()
        vulnerabilities += self._check_windows_firewall()
        vulnerabilities += self._check_telnet_service()

        severity_breakdown = self._calculate_severity_breakdown(vulnerabilities)
        recommendations = self._generate_recommendations(vulnerabilities)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        return ScanResult(
            timestamp=start_time,
            hostname=platform.node(),
            os_info=self._get_system_info(),
            vulnerabilities=vulnerabilities,
            system_health=self._get_system_health(),
            scan_duration=duration,
            total_vulnerabilities=len(vulnerabilities),
            severity_breakdown=severity_breakdown,
            recommendations=recommendations,
        )

    # ---------- отдельные проверки ----------

    def _check_python_version(self) -> List[Vulnerability]:
        try:
            current = sys.version_info[:2]
            if current < self.MIN_SAFE_PYTHON:
                return [Vulnerability(
                    severity="HIGH",
                    title="Устаревшая версия Python",
                    description=f"Обнаружена версия Python {platform.python_version()}, "
                                f"рекомендуется {'.'.join(map(str, self.MIN_SAFE_PYTHON))}+",
                    remediation=f"Обновите Python до версии {'.'.join(map(str, self.MIN_SAFE_PYTHON))} или выше",
                    category="Безопасность пакетов",
                    affected_component="Python",
                    cve_id=None,
                    cvss_score=7.2,
                )]
        except Exception:
            pass
        return []

    def _check_openssl_version(self) -> List[Vulnerability]:
        try:
            # ssl.OPENSSL_VERSION_INFO -> (major, minor, patch, ...)
            info = ssl.OPENSSL_VERSION_INFO[:3]
            if info < self.MIN_SAFE_OPENSSL:
                return [Vulnerability(
                    severity="CRITICAL",
                    title="Устаревшая версия OpenSSL",
                    description=f"Обнаружена версия OpenSSL {ssl.OPENSSL_VERSION}, "
                                f"известны уязвимости в версиях ниже "
                                f"{'.'.join(map(str, self.MIN_SAFE_OPENSSL))}",
                    remediation=f"Обновите OpenSSL до версии {'.'.join(map(str, self.MIN_SAFE_OPENSSL))} или выше",
                    category="Безопасность пакетов",
                    affected_component="OpenSSL",
                    cve_id=None,
                    cvss_score=9.8,
                )]
        except Exception:
            pass
        return []

    def _check_open_ssh_port(self) -> List[Vulnerability]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex(("127.0.0.1", 22))
                if result == 0:
                    return [Vulnerability(
                        severity="HIGH",
                        title="Открыт опасный порт 22 (SSH)",
                        description="Локально обнаружен слушающий SSH-порт 22",
                        remediation="Убедитесь, что порт 22 не доступен из внешней сети "
                                    "(настройте брандмауэр / VPN / смените порт)",
                        category="Сетевая безопасность",
                        affected_component="Firewall",
                        cve_id=None,
                        cvss_score=7.5,
                    )]
        except Exception:
            pass
        return []

    def _check_windows_firewall(self) -> List[Vulnerability]:
        if platform.system() != "Windows":
            return []
        try:
            output = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5,
            ).stdout.lower()
            if "off" in output or "выкл" in output:
                return [Vulnerability(
                    severity="MEDIUM",
                    title="Отключен брандмауэр Windows",
                    description="Один или несколько профилей брандмауэра Windows отключены",
                    remediation="Включите брандмауэр Windows через Панель управления или netsh",
                    category="Сетевая безопасность",
                    affected_component="Windows Firewall",
                    cve_id=None,
                    cvss_score=5.5,
                )]
        except Exception:
            pass
        return []

    def _check_telnet_service(self) -> List[Vulnerability]:
        try:
            if platform.system() == "Windows":
                for svc in psutil.win_service_iter():
                    info = svc.as_dict()
                    if info.get("name", "").lower() == "tlntsvr" and info.get("status") == "running":
                        return [self._telnet_vuln()]
            else:
                for proc in psutil.process_iter(attrs=["name"]):
                    name = (proc.info.get("name") or "").lower()
                    if "telnetd" in name or name == "telnet":
                        return [self._telnet_vuln()]
        except Exception:
            pass
        return []

    @staticmethod
    def _telnet_vuln() -> Vulnerability:
        return Vulnerability(
            severity="LOW",
            title="Включена служба Telnet",
            description="Обнаружена работающая служба Telnet, передающая данные в открытом виде",
            remediation="Отключите службу Telnet и используйте SSH",
            category="Службы",
            affected_component="Telnet",
            cve_id=None,
            cvss_score=3.5,
        )

    # ---------- системная информация ----------

    def _get_system_info(self) -> Dict[str, str]:
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
        }

    def _get_system_health(self) -> Dict[str, Any]:
        try:
            disk_path = "C:\\" if platform.system() == "Windows" else "/"
            return {
                "cpu_percent": psutil.cpu_percent(interval=0.3),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage(disk_path).percent,
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            }
        except Exception:
            return {}

    def _calculate_severity_breakdown(self, vulns: List[Vulnerability]) -> Dict[str, int]:
        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for vuln in vulns:
            if vuln.severity in breakdown:
                breakdown[vuln.severity] += 1
        return breakdown

    def _generate_recommendations(self, vulns: List[Vulnerability]) -> List[str]:
        recommendations = []
        seen = set()
        for vuln in vulns:
            if vuln.remediation and vuln.remediation not in seen:
                seen.add(vuln.remediation)
                recommendations.append(vuln.remediation)
        return recommendations
