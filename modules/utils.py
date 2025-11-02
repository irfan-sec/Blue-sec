"""
Blue-sec Utility Functions
Common utilities and helper functions
"""

import os
import sys
import time
import json
import hashlib
import asyncio
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path
from loguru import logger
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm

console = Console()

def banner():
    """Display Blue-sec banner"""
    banner_text = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ██████╗ ██╗     ██╗   ██╗███████╗      ███████╗███████╗ ║
║    ██╔══██╗██║     ██║   ██║██╔════╝      ██╔════╝██╔════╝ ║
║    ██████╔╝██║     ██║   ██║█████╗  █████╗███████╗█████╗   ║
║    ██╔══██╗██║     ██║   ██║██╔══╝  ╚════╝╚════██║██╔══╝   ║
║    ██████╔╝███████╗╚██████╔╝███████╗      ███████║███████╗ ║
║    ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝      ╚══════╝╚══════╝ ║
║                                                              ║
║   Advanced Bluetooth Security Testing Framework v1.0        ║
║   Author: @irfan-sec | License: MIT                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    console.print(banner_text, style="bold cyan")
    console.print("\n⚠️  [bold red]WARNING:[/bold red] For authorized security testing only!\n")


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """Setup logging configuration"""
    logger.remove()
    
    # Console logging with colors
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
        level=log_level,
        colorize=True
    )
    
    # File logging if specified
    if log_file:
        logger.add(
            log_file,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function} - {message}",
            level=log_level,
            rotation="10 MB",
            retention="30 days",
            compression="zip"
        )


def check_privileges() -> bool:
    """Check if running with elevated privileges"""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:  # Unix-like
        return os.geteuid() == 0


def require_privileges():
    """Require elevated privileges or exit"""
    if not check_privileges():
        console.print("[bold red]Error:[/bold red] This tool requires root/administrator privileges!", style="red")
        console.print("Please run with: sudo python3 blue-sec.py", style="yellow")
        sys.exit(1)


def confirm_action(message: str, default: bool = False) -> bool:
    """Ask user for confirmation"""
    return Confirm.ask(f"[yellow]{message}[/yellow]", default=default)


def format_mac_address(mac: str) -> str:
    """Format MAC address to standard format"""
    # Remove any separators
    mac = mac.replace(':', '').replace('-', '').replace('.', '').upper()
    # Add colons
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2))


def validate_mac_address(mac: str) -> bool:
    """Validate MAC address format"""
    try:
        formatted = format_mac_address(mac)
        parts = formatted.split(':')
        return len(parts) == 6 and all(len(p) == 2 for p in parts)
    except:
        return False


def calculate_hash(data: str, algorithm: str = "sha256") -> str:
    """Calculate hash of data"""
    h = hashlib.new(algorithm)
    h.update(data.encode('utf-8'))
    return h.hexdigest()


def timestamp() -> str:
    """Get current timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def timestamp_filename() -> str:
    """Get timestamp for filename"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def create_directory(path: str):
    """Create directory if it doesn't exist"""
    Path(path).mkdir(parents=True, exist_ok=True)


def save_json(data: Any, filepath: str):
    """Save data to JSON file"""
    try:
        create_directory(os.path.dirname(filepath))
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"Data saved to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Error saving JSON: {e}")
        return False


def load_json(filepath: str) -> Optional[Dict]:
    """Load data from JSON file"""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading JSON: {e}")
        return None


def display_table(title: str, columns: List[str], rows: List[List[str]]):
    """Display data in a table"""
    table = Table(title=title, show_header=True, header_style="bold magenta")
    
    for column in columns:
        table.add_column(column)
    
    for row in rows:
        table.add_row(*[str(item) for item in row])
    
    console.print(table)


def display_panel(title: str, content: str, style: str = "cyan"):
    """Display content in a panel"""
    panel = Panel(content, title=title, border_style=style)
    console.print(panel)


def progress_spinner(description: str):
    """Create a progress spinner context"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    )


async def rate_limit(calls_per_second: float):
    """Rate limiting utility"""
    delay = 1.0 / calls_per_second
    await asyncio.sleep(delay)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to remove invalid characters"""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename


def bytes_to_human_readable(bytes_value: int) -> str:
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def truncate_string(s: str, max_length: int = 50) -> str:
    """Truncate string to max length"""
    if len(s) <= max_length:
        return s
    return s[:max_length-3] + "..."


class RateLimiter:
    """Rate limiter for API calls and operations"""
    
    def __init__(self, max_calls: int, time_window: float):
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
    
    def can_proceed(self) -> bool:
        """Check if operation can proceed"""
        now = time.time()
        # Remove old calls outside the time window
        self.calls = [call_time for call_time in self.calls if now - call_time < self.time_window]
        
        if len(self.calls) < self.max_calls:
            self.calls.append(now)
            return True
        return False
    
    async def wait_if_needed(self):
        """Wait if rate limit is reached"""
        while not self.can_proceed():
            await asyncio.sleep(0.1)


class AuditLogger:
    """Audit logger for security operations"""
    
    def __init__(self, log_path: str = "reports/audit.log"):
        self.log_path = log_path
        create_directory(os.path.dirname(log_path))
    
    def log_event(self, event_type: str, details: Dict[str, Any], severity: str = "INFO"):
        """Log security event"""
        event = {
            'timestamp': timestamp(),
            'event_type': event_type,
            'severity': severity,
            'details': details
        }
        
        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            logger.error(f"Error writing audit log: {e}")
    
    def log_attack(self, attack_type: str, target: str, result: str):
        """Log attack attempt"""
        self.log_event(
            'attack_attempt',
            {
                'attack_type': attack_type,
                'target': target,
                'result': result
            },
            severity='WARNING'
        )
    
    def log_access(self, operation: str, user: str, resource: str):
        """Log access attempt"""
        self.log_event(
            'access',
            {
                'operation': operation,
                'user': user,
                'resource': resource
            },
            severity='INFO'
        )
