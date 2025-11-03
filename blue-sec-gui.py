#!/usr/bin/env python3
"""
Blue-sec GUI - Graphical User Interface Entry Point
Author: @irfan-sec
License: MIT
"""

import sys
from pathlib import Path

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from modules import load_config, banner
from modules.gui import run_gui


def main():
    """Main entry point for GUI"""
    # Print banner to console
    banner()
    
    print("\n[*] Starting Blue-sec GUI...")
    print("[*] Note: Some features require elevated privileges")
    print("[*] For authorized security testing only!\n")
    
    # Load configuration
    config = load_config()
    
    # Run GUI
    try:
        run_gui(config)
    except KeyboardInterrupt:
        print("\n[!] GUI closed by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
