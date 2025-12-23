"""
Zeek log parser for connection logs.
Converts Zeek conn.log entries into structured flow records.
"""
import re
from datetime import datetime
from typing import Dict, Optional, List
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class ZeekLogParser:
    """Parser for Zeek connection logs."""
    
    # Zeek conn.log field names (standard format)
    CONN_LOG_FIELDS = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
        'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
        'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
        'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
        'tunnel_parents', 'ip_proto'  # ip_proto added in Zeek 8.0+
    ]
    
    def __init__(self, field_separator: str = '\t', unset_field: str = '-'):
        """
        Initialize parser.
        
        Args:
            field_separator: Field separator (default: tab)
            unset_field: Placeholder for unset fields (default: '-')
        """
        self.field_separator = field_separator
        self.unset_field = unset_field
        self.field_names = None
    
    def parse_header(self, lines: List[str]) -> Optional[List[str]]:
        """
        Extract field names from Zeek log header.
        
        Args:
            lines: First few lines of the log file
        
        Returns:
            List of field names or None if not found
        """
        for line in lines:
            if line.startswith('#fields'):
                # Extract field names: #fields	ts	uid	id.orig_h ...
                parts = line.strip().split(self.field_separator)
                return parts[1:]  # Skip '#fields' itself
        return None
    
    def parse_line(self, line: str, field_names: List[str] = None) -> Optional[Dict]:
        """
        Parse a single line from Zeek conn.log.
        
        Args:
            line: Line from log file
            field_names: Field names (if None, use default)
        
        Returns:
            Dictionary with parsed flow data or None if invalid
        """
        # Skip comments and empty lines
        if line.startswith('#') or not line.strip():
            return None
        
        if field_names is None:
            field_names = self.field_names or self.CONN_LOG_FIELDS
        
        # Split line by separator
        values = line.strip().split(self.field_separator)
        
        # Create dictionary
        if len(values) != len(field_names):
            logger.warning(f"Line has {len(values)} fields, expected {len(field_names)}")
            return None
        
        record = {}
        for field, value in zip(field_names, values):
            # Convert unset fields to None
            if value == self.unset_field:
                record[field] = None
            else:
                record[field] = value
        
        # Parse and convert types
        return self._convert_types(record)
    
    def _convert_types(self, record: Dict) -> Dict:
        """Convert string values to appropriate types."""
        converted = {}
        
        # Timestamp
        if 'ts' in record and record['ts']:
            try:
                converted['timestamp'] = datetime.fromtimestamp(float(record['ts']))
            except (ValueError, TypeError):
                converted['timestamp'] = None
        
        # Connection identifiers
        converted['uid'] = record.get('uid')
        converted['orig_ip'] = record.get('id.orig_h')
        converted['orig_port'] = self._to_int(record.get('id.orig_p'))
        converted['resp_ip'] = record.get('id.resp_h')
        converted['resp_port'] = self._to_int(record.get('id.resp_p'))
        
        # Protocol and service
        converted['protocol'] = record.get('proto')
        converted['service'] = record.get('service')
        
        # Flow statistics (numeric fields)
        converted['duration'] = self._to_float(record.get('duration'))
        converted['orig_bytes'] = self._to_int(record.get('orig_bytes'))
        converted['resp_bytes'] = self._to_int(record.get('resp_bytes'))
        converted['orig_pkts'] = self._to_int(record.get('orig_pkts'))
        converted['resp_pkts'] = self._to_int(record.get('resp_pkts'))
        converted['orig_ip_bytes'] = self._to_int(record.get('orig_ip_bytes'))
        converted['resp_ip_bytes'] = self._to_int(record.get('resp_ip_bytes'))
        
        # Connection state
        converted['conn_state'] = record.get('conn_state')
        
        # Store original record for reference
        converted['zeek_metadata'] = record
        
        return converted
    
    def _to_int(self, value) -> Optional[int]:
        """Safely convert to integer."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
    
    def _to_float(self, value) -> Optional[float]:
        """Safely convert to float."""
        if value is None:
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None
    
    def parse_file(self, file_path: Path) -> List[Dict]:
        """
        Parse entire Zeek conn.log file.
        
        Args:
            file_path: Path to conn.log file
        
        Returns:
            List of parsed flow records
        """
        records = []
        
        try:
            with open(file_path, 'r') as f:
                # Read first few lines to get header
                first_lines = []
                for _ in range(10):
                    line = f.readline()
                    if not line:
                        break
                    first_lines.append(line)
                
                # Extract field names from header
                field_names = self.parse_header(first_lines)
                if field_names:
                    self.field_names = field_names
                    logger.info(f"Detected {len(field_names)} fields in Zeek log")
                
                # Reset to beginning and parse all lines
                f.seek(0)
                for line_num, line in enumerate(f, 1):
                    record = self.parse_line(line, self.field_names)
                    if record:
                        records.append(record)
                    
                    if line_num % 10000 == 0:
                        logger.debug(f"Parsed {line_num} lines, {len(records)} valid records")
            
            logger.info(f"Parsed {len(records)} flow records from {file_path}")
            return records
            
        except Exception as e:
            logger.error(f"Error parsing Zeek log {file_path}: {e}")
            return []
    
    def tail_file(self, file_path: Path, start_position: int = 0) -> tuple[List[Dict], int]:
        """
        Read new entries from log file (tail mode).
        
        Args:
            file_path: Path to conn.log file
            start_position: Byte position to start reading from
        
        Returns:
            Tuple of (list of new records, new file position)
        """
        records = []
        
        try:
            with open(file_path, 'r') as f:
                # Seek to last position
                f.seek(start_position)
                
                # Read new lines
                for line in f:
                    record = self.parse_line(line, self.field_names)
                    if record:
                        records.append(record)
                
                # Get new position
                new_position = f.tell()
            
            return records, new_position
            
        except Exception as e:
            logger.error(f"Error tailing Zeek log {file_path}: {e}")
            return [], start_position
