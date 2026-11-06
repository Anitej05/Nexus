from pathlib import Path

import pytest
from nexus_api.operations.imports import parse_csv_bundle
from nexus_api.operations.registry import validate_domain


def bundle():
    folder = Path(__file__).parents[2] / 'fixtures/operations_engine_construction_sample'
    return {file.name: file.read_text(encoding='utf-8') for file in folder.iterdir()
            if file.suffix in ('.csv', '.json')}


def test_imports_real_construction_bundle():
    parsed = parse_csv_bundle(bundle())
    result = validate_domain('construction', parsed)
    assert len(result['tasks']) >= 12
    assert isinstance(result['tasks'][0]['quantity'], (float, int))
    assert isinstance(result['tasks'][0]['resources'], dict)


@pytest.mark.parametrize('mutation', ['filename', 'duplicate', 'unknown', 'number', 'json',
                                     'oversize', 'settings', 'extra_cell'])
def test_rejects_invalid_bundle(mutation):
    files = bundle()
    if mutation == 'filename':
        files['../tasks.csv'] = files.pop('tasks.csv')
    elif mutation == 'duplicate':
        files['tasks.csv'] = 'id,id\na,b\n'
    elif mutation == 'unknown':
        files['projects.csv'] = 'id,unexpected\np,1\n'
    elif mutation == 'number':
        files['resources.csv'] = 'id,capacity,unit\nr,NaN,crew\n'
    elif mutation == 'json':
        files['materials.csv'] = 'id,unit,deliveries\nm,kg,{broken\n'
    elif mutation == 'oversize':
        files['projects.csv'] = 'x' * (2 * 1024 * 1024 + 1)
    elif mutation == 'settings':
        files['settings.json'] = '{"start_date":"2026-01-01","budget":NaN}'
    else:
        files['projects.csv'] = 'id\np,extra\n'
    with pytest.raises(ValueError):
        parse_csv_bundle(files)


def test_blank_optional_fields_are_omitted():
    files = bundle()
    files['projects.csv'] = 'id,name,deadline\np,Example,\n'
    assert parse_csv_bundle(files)['projects'] == [{'id': 'p', 'name': 'Example'}]
