#!/bin/bash
set -e

echo "Setting up virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Cloning MITRE CTI data..."
if [ ! -d "cti" ]; then
    git clone https://github.com/mitre/cti.git
else
    echo "MITRE CTI repo already exists. Pulling latest..."
    cd cti
    git pull
    cd ..
fi

echo "Attempting to download Kaggle dataset..."
if [ -f ~/.kaggle/kaggle.json ]; then
    if [ ! -d "threat_data" ]; then
        mkdir threat_data
        kaggle datasets download -d chuneeb/ai-cybersecurity-threat-dataset-2026 -p ./threat_data --unzip || echo "Warning: Kaggle download failed. Proceeding without it."
    else
        echo "Kaggle dataset already exists."
    fi
else
    echo "Warning: ~/.kaggle/kaggle.json not found. Skipping Kaggle dataset download. The system will fall back to MITRE data only."
fi

echo "Setup complete."
