"""
Capture network traffic using Zeek.
Interfaces with Zeek to capture connection logs.
"""
import subprocess
import argparse
import time
from pathlib import Path
import logging
import signal
import sys

from app.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def capture_traffic(
    interface: str = None,
    duration_hours: int = None,
    output_dir: Path = None
):
    """
    Capture network traffic using Zeek.
    
    Args:
        interface: Network interface to capture from
        duration_hours: Duration to capture (None = indefinite)
        output_dir: Directory to store Zeek logs
    """
    interface = interface or settings.NETWORK_INTERFACE
    output_dir = output_dir or settings.ZEEK_LOG_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info("Starting traffic capture with Zeek")
    logger.info(f"  Interface: {interface}")
    logger.info(f"  Output directory: {output_dir}")
    if duration_hours:
        logger.info(f"  Duration: {duration_hours} hours")
    else:
        logger.info(f"  Duration: indefinite (until interrupted)")
    
    # Find Zeek binary
    zeek_binary = None
    possible_paths = [
        '/opt/zeek/bin/zeek',  # Standard installation
        '/usr/bin/zeek',       # Package manager
        '/usr/local/bin/zeek', # Manual install
        'zeek'                 # In PATH
    ]
    
    for path in possible_paths:
        try:
            result = subprocess.run(
                [path, '--version'],
                capture_output=True,
                text=True,
                check=True
            )
            zeek_binary = path
            logger.info(f"Zeek version: {result.stdout.strip()}")
            logger.info(f"Using Zeek binary: {zeek_binary}")
            break
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    
    if not zeek_binary:
        logger.error("Zeek is not installed or not found")
        logger.error("Install Zeek: https://zeek.org/get-zeek/")
        logger.error("Checked paths: " + ", ".join(possible_paths[:-1]))
        return
    
    # Build Zeek command
    # zeek -i <interface> -C local
    # -i: interface to capture from
    # -C: ignore checksums (useful for VMs/Docker)
    # local: load local configuration
    zeek_cmd = [
        zeek_binary,  # Use full path to Zeek
        '-i', interface,
        '-C',  # Ignore checksums
        'local'  # Load local configuration
    ]
    
    logger.info(f"Starting Zeek: {' '.join(zeek_cmd)}")
    logger.info(f"Logs will be appended to {output_dir}/conn.log")
    logger.info("Note: You may need sudo privileges to capture on interface")
    logger.info("Press Ctrl+C to stop capture")
    
    # Start Zeek process
    try:
        # Create timestamped subdirectory to avoid overwriting
        import os
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        temp_dir = (output_dir / f'capture_{timestamp}').resolve()  # Absolute path
        temp_dir.mkdir(parents=True, exist_ok=True)
        os.chdir(temp_dir)
        logger.info(f"Zeek running in temporary directory: {temp_dir}")
        
        process = subprocess.Popen(
            zeek_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Setup signal handler for graceful shutdown
        def signal_handler(sig, frame):
            logger.info("\nStopping Zeek capture...")
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.warning("Zeek did not stop gracefully, forcing...")
                process.kill()
            logger.info("Capture stopped")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # If duration specified, wait and then stop
        if duration_hours:
            duration_seconds = duration_hours * 3600
            logger.info(f"Capturing for {duration_hours} hours...")
            
            start_time = time.time()
            while time.time() - start_time < duration_seconds:
                # Check if process is still running
                if process.poll() is not None:
                    logger.error("Zeek process stopped unexpectedly")
                    stderr = process.stderr.read()
                    if stderr:
                        logger.error(f"Zeek error: {stderr}")
                    return
                
                # Sleep and show progress
                time.sleep(60)  # Check every minute
                elapsed = time.time() - start_time
                remaining = duration_seconds - elapsed
                logger.info(
                    f"Elapsed: {elapsed/3600:.1f}h / {duration_hours}h "
                    f"(Remaining: {remaining/3600:.1f}h)"
                )
            
            # Stop Zeek
            logger.info("Capture duration reached, stopping Zeek...")
            process.terminate()
            process.wait(timeout=10)
            logger.info("Capture completed successfully")
            
            # Append conn.log to main file
            temp_conn_log = temp_dir / 'conn.log'
            main_conn_log = output_dir.resolve() / 'conn.log'  # Absolute path
            
            if temp_conn_log.exists():
                logger.info(f"Appending captured flows to {main_conn_log}")
                
                # Read new flows (skip header lines starting with #)
                with open(temp_conn_log, 'r') as f:
                    lines = [line for line in f if not line.startswith('#')]
                
                # Append to main conn.log
                with open(main_conn_log, 'a') as f:
                    f.writelines(lines)
                
                logger.info(f"Appended {len(lines)} flow records to main log")
            else:
                logger.warning(f"No conn.log found in {temp_dir}")
            
            # Clean up temp directory
            import shutil
            os.chdir(output_dir.resolve())  # Go back to output dir before deleting
            shutil.rmtree(temp_dir)
            logger.info(f"Cleaned up temporary directory {temp_dir}")
        
        else:
            # Run indefinitely until interrupted
            logger.info("Zeek is running... (Press Ctrl+C to stop)")
            process.wait()
    
    except PermissionError:
        logger.error(
            f"Permission denied to capture on interface {interface}"
        )
        logger.error("Try running with sudo: sudo poetry run capture-traffic")
    
    except Exception as e:
        logger.error(f"Error during capture: {e}")
        if 'process' in locals():
            process.terminate()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Capture network traffic using Zeek'
    )
    parser.add_argument(
        '--interface',
        type=str,
        default=None,
        help=f'Network interface (default: {settings.NETWORK_INTERFACE})'
    )
    parser.add_argument(
        '--duration',
        type=int,
        default=None,
        help='Duration in hours (default: indefinite)'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=None,
        help=f'Output directory (default: {settings.ZEEK_LOG_DIR})'
    )
    
    args = parser.parse_args()
    
    capture_traffic(
        interface=args.interface,
        duration_hours=args.duration,
        output_dir=args.output_dir
    )


if __name__ == '__main__':
    main()
