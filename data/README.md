# Data Directory

Raw data files are **gitignored** — this directory contains only download scripts.

## CICIDS-2017 Dataset

**Homepage**: https://www.unb.ca/cic/datasets/ids-2017.html

Download the dataset CSV files:
```
python data/download_cicids.py          # downloads all 5 days (~8GB total)
python data/download_cicids.py --day tuesday  # single day only
```

Files are saved to `data/cicids/` (gitignored).

## MITRE ATT&CK STIX Bundle

Downloaded automatically by `download_cicids.py` as `data/enterprise-attack.json` (~12MB, gitignored).
Required by `models/mitre_mapper.py`.

## Synthetic Sample (CI/CD)

```
python data/sample/generate_sample.py   # generates data/sample/cicids_sample.csv
```

1,000-row synthetic dataset for unit tests and model smoke tests.
No download required. Output file is gitignored.
