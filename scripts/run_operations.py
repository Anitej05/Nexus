"""Run the authenticated operations application; local SQLite or configured PostgreSQL."""

import argparse
import os
from pathlib import Path

import uvicorn
from nexus_api.operations.api import create_operations_app

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8090)
    parser.add_argument('--database', default=None)
    args = parser.parse_args()
    env_file = Path(__file__).resolve().parents[1] / '.env.operations'
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            key, separator, value = line.partition('=')
            if separator and key in ('NVIDIA_API_KEY', 'NEXUS_LLM_MODEL'):
                os.environ.setdefault(key, value.strip())
    database = args.database or os.environ.get('NEXUS_OPERATIONS_DATABASE_URL')
    if not database:
        folder = Path(__file__).resolve().parents[1] / 'artifacts/operations'
        folder.mkdir(parents=True, exist_ok=True)
        database = str(folder / 'operations.sqlite')
    if '://' not in database:
        database = 'sqlite+aiosqlite:///' + str(Path(database).resolve())
    uvicorn.run(create_operations_app(database), host='127.0.0.1', port=args.port)
