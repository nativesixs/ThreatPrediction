import kagglehub
import os
import shutil
from pathlib import Path


class DatasetDownloader:
    def __init__(self, data_dir: str = "./data/raw"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.datasets = {
            "tii-ssrc-23": "daniaherzalla/tii-ssrc-23",
            "ics-flow": "alirezadehlaghi/icssim",
            "nsl-kdd": "hassan06/nslkdd",
            "unsw-nb15": "alextamboli/unsw-nb15",
            "cse-cic-ids2018": "solarmainframe/ids-intrusion-csv"
        }
    
    def download_dataset(self, name: str) -> str:
        if name not in self.datasets:
            raise ValueError(f"Unknown dataset: {name}. Available: {list(self.datasets.keys())}")
        
        print(f"Downloading {name}...")
        path = kagglehub.dataset_download(self.datasets[name])
        
        target_dir = self.data_dir / name
        if target_dir.exists():
            shutil.rmtree(target_dir)
        
        shutil.copytree(path, target_dir)
        print(f"Dataset {name} saved to {target_dir}")
        
        return str(target_dir)
    
    def download_all(self):
        for name in self.datasets.keys():
            try:
                self.download_dataset(name)
            except Exception as e:
                print(f"Error downloading {name}: {e}")
        
        print("\nAll datasets downloaded successfully!")
        self.list_datasets()
    
    def list_datasets(self):
        print("\nDataset locations:")
        for name in self.datasets.keys():
            dataset_path = self.data_dir / name
            if dataset_path.exists():
                size = sum(f.stat().st_size for f in dataset_path.rglob('*') if f.is_file())
                size_mb = size / (1024 * 1024)
                print(f"  {name}: {dataset_path} ({size_mb:.2f} MB)")


def download_all_datasets():
    """Entry point for poetry script"""
    downloader = DatasetDownloader()
    downloader.download_all()


if __name__ == "__main__":
    download_all_datasets()
