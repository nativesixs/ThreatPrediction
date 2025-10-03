"""
Unified Dataset Creation Pipeline

This script extracts common features from all 5 datasets and creates
a single unified training dataset with consistent features and labels.

Usage:
    poetry run python scripts/create_unified_dataset.py
"""

import pandas as pd
import numpy as np
from pathlib import Path
import json
from typing import Dict, List, Tuple
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

# Paths
BASE_DIR = Path(__file__).parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
PROCESSED_DIR.mkdir(exist_ok=True)

# ============================================================================
# UNIFIED FEATURE SET (35 features)
# ============================================================================

UNIFIED_FEATURES = [
    # Flow basics (5)
    'duration',
    'protocol',
    'total_fwd_packets',
    'total_bwd_packets',
    'total_packets',
    
    # Byte statistics (6)
    'total_fwd_bytes',
    'total_bwd_bytes',
    'fwd_bytes_max',
    'fwd_bytes_min',
    'fwd_bytes_mean',
    'fwd_bytes_std',
    
    # Backward bytes statistics (4)
    'bwd_bytes_max',
    'bwd_bytes_min',
    'bwd_bytes_mean',
    'bwd_bytes_std',
    
    # Rate features (4)
    'flow_packets_per_sec',
    'flow_bytes_per_sec',
    'fwd_packets_per_sec',
    'bwd_packets_per_sec',
    
    # Inter-arrival time (4)
    'fwd_iat_mean',
    'fwd_iat_std',
    'bwd_iat_mean',
    'bwd_iat_std',
    
    # TCP flags (6)
    'syn_flag_count',
    'ack_flag_count',
    'fin_flag_count',
    'rst_flag_count',
    'psh_flag_count',
    'urg_flag_count',
    
    # Behavioral (6)
    'active_mean',
    'active_std',
    'idle_mean',
    'idle_std',
    'down_up_ratio',
    'fwd_header_length',
]

# ============================================================================
# UNIFIED LABEL TAXONOMY (7 categories)
# ============================================================================

UNIFIED_LABELS = {
    'NORMAL': 0,
    'DOS': 1,
    'PROBE': 2,
    'R2L': 3,
    'U2R': 4,
    'MALWARE': 5,
    'EXPLOIT': 6,
}

# Label mapping for each dataset
LABEL_MAPPING = {
    'nsl-kdd': {
        'normal': 'NORMAL',
        # DoS attacks
        'neptune': 'DOS', 'smurf': 'DOS', 'back': 'DOS', 'teardrop': 'DOS', 
        'pod': 'DOS', 'land': 'DOS', 'apache2': 'DOS', 'udpstorm': 'DOS',
        'processtable': 'DOS', 'mailbomb': 'DOS',
        # Probe attacks
        'portsweep': 'PROBE', 'nmap': 'PROBE', 'satan': 'PROBE', 
        'ipsweep': 'PROBE', 'saint': 'PROBE', 'mscan': 'PROBE',
        # R2L attacks
        'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L',
        'multihop': 'R2L', 'phf': 'R2L', 'warezmaster': 'R2L',
        'warezclient': 'R2L', 'spy': 'R2L', 'xlock': 'R2L',
        'snmpguess': 'R2L', 'snmpgetattack': 'R2L', 'httptunnel': 'R2L',
        'sendmail': 'R2L', 'named': 'R2L', 'xsnoop': 'R2L',
        # U2R attacks
        'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R',
        'rootkit': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R',
        'ps': 'U2R',
    },
    'unsw-nb15': {
        'Normal': 'NORMAL',
        'DoS': 'DOS',
        'Reconnaissance': 'PROBE',
        'Analysis': 'PROBE',
        'Fuzzers': 'EXPLOIT',
        'Exploits': 'EXPLOIT',
        'Shellcode': 'EXPLOIT',
        'Backdoor': 'MALWARE',
        'Backdoors': 'MALWARE',
        'Worms': 'MALWARE',
        'Generic': 'EXPLOIT',
    },
    'cic-ids2018': {
        'Benign': 'NORMAL',
        # DoS/DDoS
        'DoS': 'DOS',
        'DDoS': 'DOS',
        'DoS attacks-Hulk': 'DOS',
        'DoS attacks-SlowHTTPTest': 'DOS',
        'DoS attacks-Slowloris': 'DOS',
        'DoS attacks-GoldenEye': 'DOS',
        'DDOS attack-HOIC': 'DOS',
        'DDOS attack-LOIC-UDP': 'DOS',
        # Reconnaissance
        'PortScan': 'PROBE',
        # Brute force
        'FTP-BruteForce': 'R2L',
        'SSH-Bruteforce': 'R2L',
        'Brute Force': 'R2L',
        'Brute Force -Web': 'R2L',
        'Brute Force -XSS': 'R2L',
        # Web attacks
        'Web Attack': 'EXPLOIT',
        'SQL Injection': 'EXPLOIT',
        'Infiltration': 'EXPLOIT',
        # Malware
        'Bot': 'MALWARE',
        'Botnet': 'MALWARE',
    },
    'tii-ssrc-23': {
        'Benign': 'NORMAL',
        'Malicious': 'EXPLOIT',  # Default for binary
    },
    'ics-flow': {
        'Normal': 'NORMAL',
        'Attack': 'EXPLOIT',
        'Malicious': 'EXPLOIT',
    }
}

# ============================================================================
# FEATURE MAPPING (Dataset-specific columns → Unified features)
# ============================================================================

# NSL-KDD column names (no header in file)
NSL_KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class', 'difficulty'
]

def extract_nsl_kdd_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract unified features from NSL-KDD dataset."""
    print("  Mapping NSL-KDD features...")
    
    # Add column names if not present
    if 'protocol_type' not in df.columns:
        df.columns = NSL_KDD_COLUMNS[:len(df.columns)]
    
    # Protocol encoding
    protocol_map = {'tcp': 1, 'udp': 2, 'icmp': 3}
    df['protocol_encoded'] = df['protocol_type'].map(protocol_map).fillna(0)
    
    unified = pd.DataFrame()
    unified['duration'] = df['duration']
    unified['protocol'] = df['protocol_encoded']
    unified['total_fwd_packets'] = df['count']  # Approximate
    unified['total_bwd_packets'] = df['srv_count']  # Approximate
    unified['total_packets'] = df['count'] + df['srv_count']
    
    unified['total_fwd_bytes'] = df['src_bytes']
    unified['total_bwd_bytes'] = df['dst_bytes']
    
    # Derive statistics (NSL-KDD doesn't have detailed packet stats)
    unified['fwd_bytes_max'] = df['src_bytes']
    unified['fwd_bytes_min'] = df['src_bytes'] * 0.5  # Estimated
    unified['fwd_bytes_mean'] = df['src_bytes']
    unified['fwd_bytes_std'] = df['src_bytes'] * 0.3  # Estimated
    
    unified['bwd_bytes_max'] = df['dst_bytes']
    unified['bwd_bytes_min'] = df['dst_bytes'] * 0.5
    unified['bwd_bytes_mean'] = df['dst_bytes']
    unified['bwd_bytes_std'] = df['dst_bytes'] * 0.3
    
    # Rates
    unified['flow_packets_per_sec'] = unified['total_packets'] / (df['duration'] + 1e-6)
    unified['flow_bytes_per_sec'] = (df['src_bytes'] + df['dst_bytes']) / (df['duration'] + 1e-6)
    unified['fwd_packets_per_sec'] = df['count'] / (df['duration'] + 1e-6)
    unified['bwd_packets_per_sec'] = df['srv_count'] / (df['duration'] + 1e-6)
    
    # Inter-arrival times (estimated from counts)
    unified['fwd_iat_mean'] = df['duration'] / (df['count'] + 1)
    unified['fwd_iat_std'] = unified['fwd_iat_mean'] * 0.5
    unified['bwd_iat_mean'] = df['duration'] / (df['srv_count'] + 1)
    unified['bwd_iat_std'] = unified['bwd_iat_mean'] * 0.5
    
    # TCP flags (NSL-KDD has aggregated flags)
    unified['syn_flag_count'] = df['su_attempted'] * 2  # Estimated
    unified['ack_flag_count'] = df['count']  # Most packets have ACK
    unified['fin_flag_count'] = df['serror_rate'] * df['count']
    unified['rst_flag_count'] = df['rerror_rate'] * df['count']
    unified['psh_flag_count'] = df['count'] * 0.5
    unified['urg_flag_count'] = df['urgent']
    
    # Behavioral
    unified['active_mean'] = df['duration'] * 0.7
    unified['active_std'] = df['duration'] * 0.2
    unified['idle_mean'] = df['duration'] * 0.3
    unified['idle_std'] = df['duration'] * 0.1
    unified['down_up_ratio'] = df['dst_bytes'] / (df['src_bytes'] + 1)
    unified['fwd_header_length'] = df['count'] * 20  # Estimated
    
    # Label
    unified['label_str'] = df['class'].str.strip()
    unified['dataset'] = 'nsl-kdd'
    
    return unified


def extract_unsw_nb15_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract unified features from UNSW-NB15 dataset."""
    print("  Mapping UNSW-NB15 features...")
    
    # Protocol encoding
    protocol_map = {'tcp': 1, 'udp': 2, 'icmp': 3}
    df['protocol_encoded'] = df['proto'].map(protocol_map).fillna(0)
    
    unified = pd.DataFrame()
    unified['duration'] = df['dur']
    unified['protocol'] = df['protocol_encoded']
    unified['total_fwd_packets'] = df['spkts']
    unified['total_bwd_packets'] = df['dpkts']
    unified['total_packets'] = df['spkts'] + df['dpkts']
    
    unified['total_fwd_bytes'] = df['sbytes']
    unified['total_bwd_bytes'] = df['dbytes']
    
    # Byte statistics
    unified['fwd_bytes_max'] = df['sbytes']
    unified['fwd_bytes_min'] = df['sbytes'] * 0.5
    unified['fwd_bytes_mean'] = df['sbytes'] / (df['spkts'] + 1)
    unified['fwd_bytes_std'] = unified['fwd_bytes_mean'] * 0.3
    
    unified['bwd_bytes_max'] = df['dbytes']
    unified['bwd_bytes_min'] = df['dbytes'] * 0.5
    unified['bwd_bytes_mean'] = df['dbytes'] / (df['dpkts'] + 1)
    unified['bwd_bytes_std'] = unified['bwd_bytes_mean'] * 0.3
    
    # Rates
    unified['flow_packets_per_sec'] = df['rate']
    unified['flow_bytes_per_sec'] = (df['sbytes'] + df['dbytes']) / (df['dur'] + 1e-6)
    unified['fwd_packets_per_sec'] = df['spkts'] / (df['dur'] + 1e-6)
    unified['bwd_packets_per_sec'] = df['dpkts'] / (df['dur'] + 1e-6)
    
    # Inter-arrival times
    unified['fwd_iat_mean'] = df['sinpkt']
    unified['fwd_iat_std'] = df['sjit']
    unified['bwd_iat_mean'] = df['dinpkt']
    unified['bwd_iat_std'] = df['djit']
    
    # TCP flags
    unified['syn_flag_count'] = df.get('swin', 0) * 0.1
    unified['ack_flag_count'] = df['spkts'] * 0.8
    unified['fin_flag_count'] = df.get('stcpb', 0) * 0.1
    unified['rst_flag_count'] = df.get('dtcpb', 0) * 0.1
    unified['psh_flag_count'] = df['spkts'] * 0.5
    unified['urg_flag_count'] = 0
    
    # Behavioral
    unified['active_mean'] = df.get('smeansz', 0)
    unified['active_std'] = df.get('dmeansz', 0)
    unified['idle_mean'] = df['dur'] * 0.3
    unified['idle_std'] = df['dur'] * 0.1
    unified['down_up_ratio'] = df['dbytes'] / (df['sbytes'] + 1)
    unified['fwd_header_length'] = df.get('sloss', 0)
    
    # Label
    unified['label_str'] = df['attack_cat'] if 'attack_cat' in df.columns else 'Normal'
    unified['dataset'] = 'unsw-nb15'
    
    return unified


def extract_cic_ids2018_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract unified features from CSE-CIC-IDS2018 dataset."""
    print("  Mapping CIC-IDS2018 features...")
    
    # Clean column names
    df.columns = df.columns.str.strip()
    
    # Protocol encoding
    protocol_map = {6: 1, 17: 2, 1: 3}  # TCP, UDP, ICMP
    df['protocol_encoded'] = df['Protocol'].map(protocol_map).fillna(0)
    
    unified = pd.DataFrame()
    unified['duration'] = df['Flow Duration'].fillna(0)
    unified['protocol'] = df['protocol_encoded']
    unified['total_fwd_packets'] = df['Tot Fwd Pkts']
    unified['total_bwd_packets'] = df['Tot Bwd Pkts']
    unified['total_packets'] = unified['total_fwd_packets'] + unified['total_bwd_packets']
    
    unified['total_fwd_bytes'] = df['TotLen Fwd Pkts']
    unified['total_bwd_bytes'] = df['TotLen Bwd Pkts']
    
    # Byte statistics
    unified['fwd_bytes_max'] = df['Fwd Pkt Len Max']
    unified['fwd_bytes_min'] = df['Fwd Pkt Len Min']
    unified['fwd_bytes_mean'] = df['Fwd Pkt Len Mean']
    unified['fwd_bytes_std'] = df['Fwd Pkt Len Std']
    
    unified['bwd_bytes_max'] = df['Bwd Pkt Len Max']
    unified['bwd_bytes_min'] = df['Bwd Pkt Len Min']
    unified['bwd_bytes_mean'] = df['Bwd Pkt Len Mean']
    unified['bwd_bytes_std'] = df['Bwd Pkt Len Std']
    
    # Rates
    unified['flow_packets_per_sec'] = df['Flow Pkts/s']
    unified['flow_bytes_per_sec'] = df['Flow Byts/s']
    unified['fwd_packets_per_sec'] = df['Fwd Pkts/s']
    unified['bwd_packets_per_sec'] = df['Bwd Pkts/s']
    
    # Inter-arrival times
    unified['fwd_iat_mean'] = df['Fwd IAT Mean']
    unified['fwd_iat_std'] = df['Fwd IAT Std']
    unified['bwd_iat_mean'] = df['Bwd IAT Mean']
    unified['bwd_iat_std'] = df['Bwd IAT Std']
    
    # TCP flags
    unified['syn_flag_count'] = df['SYN Flag Cnt']
    unified['ack_flag_count'] = df['ACK Flag Cnt']
    unified['fin_flag_count'] = df['FIN Flag Cnt']
    unified['rst_flag_count'] = df['RST Flag Cnt']
    unified['psh_flag_count'] = df['PSH Flag Cnt']
    unified['urg_flag_count'] = df['URG Flag Cnt']
    
    # Behavioral
    unified['active_mean'] = df['Active Mean']
    unified['active_std'] = df['Active Std']
    unified['idle_mean'] = df['Idle Mean']
    unified['idle_std'] = df['Idle Std']
    unified['down_up_ratio'] = df['Down/Up Ratio']
    unified['fwd_header_length'] = df['Fwd Header Len']
    
    # Label
    unified['label_str'] = df['Label'].str.strip()
    unified['dataset'] = 'cic-ids2018'
    
    return unified


def extract_tii_ssrc_features(df: pd.DataFrame, sample_size: int = 1_000_000) -> pd.DataFrame:
    """Extract unified features from TII-SSRC-23 dataset (sampled)."""
    print(f"  Sampling {sample_size:,} rows from TII-SSRC-23...")
    
    # Sample for manageable size
    if len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42)
    
    print("  Mapping TII-SSRC-23 features...")
    
    # This dataset has many features - map the ones we can identify
    unified = pd.DataFrame()
    
    # Try to identify columns (column names might vary)
    cols = {col.lower(): col for col in df.columns}
    
    # Extract what we can
    unified['duration'] = df[cols.get('duration', df.columns[0])].fillna(0)
    unified['protocol'] = df[cols.get('protocol', df.columns[1])].fillna(1)
    
    # Fill remaining with estimated values or zeros
    for feat in UNIFIED_FEATURES[2:]:
        if feat in cols:
            unified[feat] = df[cols[feat]]
        else:
            unified[feat] = 0  # Default for missing features
    
    # Label (binary: Benign/Malicious)
    label_col = [col for col in df.columns if 'label' in col.lower()]
    if label_col:
        unified['label_str'] = df[label_col[0]]
    else:
        unified['label_str'] = 'Benign'  # Default
    
    unified['dataset'] = 'tii-ssrc-23'
    
    return unified


def extract_ics_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract unified features from ICS-Flow dataset."""
    print("  Mapping ICS-Flow features...")
    
    unified = pd.DataFrame()
    
    # ICS-Flow has flow-based features
    cols = {col.lower(): col for col in df.columns}
    
    unified['duration'] = df[cols.get('duration', df.columns[0])].fillna(0)
    
    # Protocol encoding (ICS-Flow uses strings like "IPV4-TCP")
    protocol_map = {'IPV4-TCP': 1, 'IPV4-UDP': 2, 'IPV4-ICMP': 3}
    if 'protocol' in cols:
        unified['protocol'] = df[cols['protocol']].map(protocol_map).fillna(1)
    else:
        unified['protocol'] = 1  # Default to TCP
    
    # Map available columns
    for feat in UNIFIED_FEATURES[2:]:
        if feat in cols:
            unified[feat] = df[cols[feat]]
        else:
            unified[feat] = 0
    
    # Label
    label_col = [col for col in df.columns if 'label' in col.lower() or 'class' in col.lower()]
    if label_col:
        unified['label_str'] = df[label_col[0]]
    else:
        unified['label_str'] = 'Normal'
    
    unified['dataset'] = 'ics-flow'
    
    return unified


# ============================================================================
# MAIN PROCESSING PIPELINE
# ============================================================================

def harmonize_labels(df: pd.DataFrame, dataset_name: str) -> pd.DataFrame:
    """Map dataset-specific labels to unified taxonomy."""
    print(f"  Harmonizing labels for {dataset_name}...")
    
    mapping = LABEL_MAPPING.get(dataset_name, {})
    df['label_unified'] = df['label_str'].map(mapping).fillna('EXPLOIT')
    df['label_numeric'] = df['label_unified'].map(UNIFIED_LABELS)
    
    return df


def process_dataset(name: str, extractor_func, file_path: Path, 
                   encoding: str = 'utf-8', sample_size: int = None) -> pd.DataFrame:
    """Load, extract, and harmonize a single dataset."""
    print(f"\n{'='*60}")
    print(f"Processing {name.upper()}")
    print(f"{'='*60}")
    
    try:
        # Load dataset
        print(f"Loading from {file_path}...")
        if sample_size:
            # Read in chunks for large files
            chunks = []
            for chunk in pd.read_csv(file_path, encoding=encoding, chunksize=100_000, 
                                    low_memory=False, on_bad_lines='skip'):
                chunks.append(chunk)
                if sum(len(c) for c in chunks) >= sample_size:
                    break
            df = pd.concat(chunks, ignore_index=True)
        else:
            df = pd.read_csv(file_path, encoding=encoding, low_memory=False, on_bad_lines='skip')
        
        print(f"  Loaded {len(df):,} rows, {len(df.columns)} columns")
        
        # Extract unified features
        unified_df = extractor_func(df)
        
        # Harmonize labels
        unified_df = harmonize_labels(unified_df, name)
        
        # Clean data
        unified_df = unified_df.replace([np.inf, -np.inf], 0)
        unified_df = unified_df.fillna(0)
        
        print(f"  ✓ Extracted {len(unified_df):,} samples")
        print(f"  Label distribution:")
        for label, count in unified_df['label_unified'].value_counts().head(5).items():
            print(f"    {label}: {count:,} ({count/len(unified_df)*100:.1f}%)")
        
        return unified_df
        
    except Exception as e:
        print(f"  ✗ Error processing {name}: {e}")
        return pd.DataFrame()


def create_unified_dataset():
    """Main function to create unified dataset."""
    print("\n" + "="*80)
    print("UNIFIED DATASET CREATION PIPELINE")
    print("="*80)
    
    datasets = []
    
    # 1. NSL-KDD (all data - baseline)
    nsl_train = RAW_DIR / "nsl-kdd" / "KDDTrain+.txt"
    nsl_test = RAW_DIR / "nsl-kdd" / "KDDTest+.txt"
    
    if nsl_train.exists():
        # Load both train and test
        df_train = process_dataset('nsl-kdd', extract_nsl_kdd_features, nsl_train)
        df_test = process_dataset('nsl-kdd', extract_nsl_kdd_features, nsl_test)
        nsl_df = pd.concat([df_train, df_test], ignore_index=True)
        datasets.append(nsl_df)
    
    # 2. UNSW-NB15 (all data - balanced)
    unsw_train = RAW_DIR / "unsw-nb15" / "UNSW-NB15_c" / "UNSW_NB15_training-set.csv"
    unsw_test = RAW_DIR / "unsw-nb15" / "UNSW-NB15_c" / "UNSW_NB15_testing-set.csv"
    
    if unsw_train.exists():
        df_train = process_dataset('unsw-nb15', extract_unsw_nb15_features, unsw_train, encoding='latin-1')
        df_test = process_dataset('unsw-nb15', extract_unsw_nb15_features, unsw_test, encoding='latin-1')
        unsw_df = pd.concat([df_train, df_test], ignore_index=True)
        datasets.append(unsw_df)
    
    # 3. CIC-IDS2018 (sample 2M - modern, diverse)
    cic_files = list((RAW_DIR / "cse-cic-ids2018").glob("*.csv"))
    if cic_files:
        cic_dfs = []
        for file in cic_files[:3]:  # Process first 3 files
            df = process_dataset('cic-ids2018', extract_cic_ids2018_features, 
                               file, sample_size=700_000)
            if not df.empty:
                cic_dfs.append(df)
        if cic_dfs:
            cic_df = pd.concat(cic_dfs, ignore_index=True)
            datasets.append(cic_df)
    
    # 4. TII-SSRC-23 (sample 1M - most recent)
    tii_file = RAW_DIR / "tii-ssrc-23" / "csv" / "data.csv"
    if tii_file.exists():
        tii_df = process_dataset('tii-ssrc-23', extract_tii_ssrc_features, 
                                tii_file, sample_size=1_000_000)
        if not tii_df.empty:
            datasets.append(tii_df)
    
    # 5. ICS-Flow (all data - specialized)
    ics_file = RAW_DIR / "ics-flow" / "Dataset.csv"
    if ics_file.exists():
        ics_df = process_dataset('ics-flow', extract_ics_flow_features, ics_file)
        if not ics_df.empty:
            datasets.append(ics_df)
    
    if not datasets:
        print("\n✗ No datasets were successfully processed!")
        return
    
    # Merge all datasets
    print("\n" + "="*80)
    print("MERGING DATASETS")
    print("="*80)
    
    unified_df = pd.concat(datasets, ignore_index=True)
    print(f"Total samples: {len(unified_df):,}")
    
    # Balance classes
    print("\nBalancing classes...")
    label_counts = unified_df['label_unified'].value_counts()
    print("Original distribution:")
    for label, count in label_counts.items():
        print(f"  {label}: {count:,} ({count/len(unified_df)*100:.1f}%)")
    
    # Sample to balance (max 500k per class)
    balanced_dfs = []
    max_samples_per_class = 500_000
    for label in unified_df['label_unified'].unique():
        label_df = unified_df[unified_df['label_unified'] == label]
        if len(label_df) > max_samples_per_class:
            label_df = label_df.sample(n=max_samples_per_class, random_state=42)
        balanced_dfs.append(label_df)
    
    balanced_df = pd.concat(balanced_dfs, ignore_index=True)
    balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"\nBalanced samples: {len(balanced_df):,}")
    print("Balanced distribution:")
    for label, count in balanced_df['label_unified'].value_counts().items():
        print(f"  {label}: {count:,} ({count/len(balanced_df)*100:.1f}%)")
    
    # Split train/val/test
    print("\nSplitting into train/val/test...")
    train_df, temp_df = train_test_split(balanced_df, test_size=0.3, 
                                         stratify=balanced_df['label_numeric'],
                                         random_state=42)
    val_df, test_df = train_test_split(temp_df, test_size=0.5,
                                       stratify=temp_df['label_numeric'],
                                       random_state=42)
    
    print(f"  Train: {len(train_df):,} samples")
    print(f"  Validation: {len(val_df):,} samples")
    print(f"  Test: {len(test_df):,} samples")
    
    # Normalize features
    print("\nNormalizing features...")
    feature_cols = UNIFIED_FEATURES
    
    # Ensure all feature columns are numeric and clean
    for df_split in [train_df, val_df, test_df]:
        for col in feature_cols:
            df_split[col] = pd.to_numeric(df_split[col], errors='coerce')
            df_split[col] = df_split[col].replace([np.inf, -np.inf], np.nan)
            df_split[col] = df_split[col].fillna(0)
    
    scaler = StandardScaler()
    train_df[feature_cols] = scaler.fit_transform(train_df[feature_cols])
    val_df[feature_cols] = scaler.transform(val_df[feature_cols])
    test_df[feature_cols] = scaler.transform(test_df[feature_cols])
    
    # Save datasets
    print("\nSaving datasets...")
    train_df.to_csv(PROCESSED_DIR / "unified_train.csv", index=False)
    val_df.to_csv(PROCESSED_DIR / "unified_val.csv", index=False)
    test_df.to_csv(PROCESSED_DIR / "unified_test.csv", index=False)
    
    # Save scaler
    import joblib
    joblib.dump(scaler, PROCESSED_DIR / "unified_scaler.pkl")
    
    # Save metadata
    metadata = {
        'total_samples': len(balanced_df),
        'train_samples': len(train_df),
        'val_samples': len(val_df),
        'test_samples': len(test_df),
        'features': UNIFIED_FEATURES,
        'num_features': len(UNIFIED_FEATURES),
        'labels': list(UNIFIED_LABELS.keys()),
        'num_classes': len(UNIFIED_LABELS),
        'dataset_sources': [df['dataset'].iloc[0] for df in datasets],
        'label_distribution': balanced_df['label_unified'].value_counts().to_dict(),
    }
    
    with open(PROCESSED_DIR / "unified_metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print("\n" + "="*80)
    print("✓ UNIFIED DATASET CREATED SUCCESSFULLY!")
    print("="*80)
    print(f"Location: {PROCESSED_DIR}")
    print(f"Files:")
    print(f"  - unified_train.csv ({len(train_df):,} samples)")
    print(f"  - unified_val.csv ({len(val_df):,} samples)")
    print(f"  - unified_test.csv ({len(test_df):,} samples)")
    print(f"  - unified_scaler.pkl")
    print(f"  - unified_metadata.json")
    print(f"\nReady for model training!")
    
    # Print file sizes
    train_size = (PROCESSED_DIR / "unified_train.csv").stat().st_size / (1024**2)
    val_size = (PROCESSED_DIR / "unified_val.csv").stat().st_size / (1024**2)
    test_size = (PROCESSED_DIR / "unified_test.csv").stat().st_size / (1024**2)
    print(f"\nDataset sizes:")
    print(f"  Train: {train_size:.1f} MB")
    print(f"  Val: {val_size:.1f} MB")
    print(f"  Test: {test_size:.1f} MB")
    print(f"  Total: {train_size+val_size+test_size:.1f} MB")


if __name__ == "__main__":
    create_unified_dataset()
