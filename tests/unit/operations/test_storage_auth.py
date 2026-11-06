import asyncio
import hashlib
import os
import time

import pytest
from nexus_api.operations.auth import (
    create_session,
    hash_password,
    lookup_session,
    revoke_session,
    verify_password,
)
from nexus_api.operations.storage import OperationsStore, StorageIntegrityError
from sqlalchemy import text


@pytest.fixture(params=['sqlite', 'postgres'])
async def store(request, tmp_path):
    url = (f'sqlite+aiosqlite:///{tmp_path}/operations.db' if request.param == 'sqlite'
           else os.environ.get('NEXUS_OPERATIONS_TEST_DATABASE_URL'))
    if not url:
        pytest.skip('Real PostgreSQL requires NEXUS_OPERATIONS_TEST_DATABASE_URL')
    result = OperationsStore(url)
    await result.initialize()
    # A prior corruption test deliberately leaves an unreadable row.
    async with result.engine.begin() as connection:
        await connection.execute(text('DELETE FROM operations_state'))
    await result.initialize()
    yield result
    await result.close()


async def test_concurrent_first_initialization(tmp_path):
    url = f'sqlite+aiosqlite:///{tmp_path}/fresh.db'
    stores = [OperationsStore(url), OperationsStore(url)]
    try:
        await asyncio.gather(*(item.initialize() for item in stores))
        async with stores[0].transaction() as state:
            assert state == {'users': {}, 'sessions': {}, 'workspaces': {},
                             'decisions': {}, 'receipts': {}}
    finally:
        await asyncio.gather(*(item.close() for item in stores))


async def test_restart_and_rollback(store):
    async with store.transaction() as state:
        state['users']['one'] = {'username': 'alice'}
    with pytest.raises(RuntimeError):
        async with store.transaction() as state:
            state['users'].clear()
            raise RuntimeError('abort')
    other = OperationsStore(store.database_url)
    await other.initialize()
    try:
        async with other.transaction() as state:
            assert state['users']['one']['username'] == 'alice'
    finally:
        await other.close()


async def test_concurrent_updates(store):
    other = OperationsStore(store.database_url)
    await asyncio.gather(store.initialize(), other.initialize())
    async def increment(target):
        async with target.transaction() as state:
            count = state['receipts'].get('count', 0)
            await asyncio.sleep(0.01)
            state['receipts']['count'] = count + 1
    try:
        await asyncio.gather(*(increment(store if n % 2 else other) for n in range(8)))
        async with store.transaction() as state:
            assert state['receipts']['count'] == 8
    finally:
        await other.close()


@pytest.mark.parametrize('malformed', [False, True])
async def test_corrupt_state(store, malformed):
    payload = '{"users":[]}' if malformed else '{}'
    digest = hashlib.sha256(payload.encode()).hexdigest() if malformed else 'broken'
    async with store.engine.begin() as connection:
        await connection.execute(text('UPDATE operations_state SET payload=:p, digest=:d'),
                                 {'p': payload, 'd': digest})
    with pytest.raises(StorageIntegrityError):
        async with store.transaction():
            pass


async def test_size_limit_rolls_back(store):
    with pytest.raises(StorageIntegrityError):
        async with store.transaction() as state:
            state['receipts']['huge'] = 'x' * (10 * 1024 * 1024)
    async with store.transaction() as state:
        assert not state['receipts']


def test_passwords():
    password = 'a long unique password'  # noqa: S105 - test input, never a deployed credential
    encoded = hash_password(password)
    assert encoded != hash_password(password)
    assert verify_password(password, encoded)
    assert not verify_password('wrong password', encoded)
    assert not verify_password(password, 'malformed')
    for invalid in ['short', 'x' * 257, '\ud800' * 12]:
        with pytest.raises(ValueError):
            hash_password(invalid)


def test_session_lifecycle():
    user = {'id': 'u1', 'username': 'alice', 'role': 'admin', 'password_hash': 'private'}
    state = {'users': {'u1': user}, 'sessions': {}}
    session = create_session(state, user)
    assert session['token'] not in repr(state)
    assert len(session['token']) >= 43
    assert 'password_hash' not in session['user']
    assert lookup_session(state, session['token'])['user']['username'] == 'alice'
    user['disabled'] = True
    assert lookup_session(state, session['token']) is None
    user['disabled'] = False
    session = create_session(state, user)
    for item in state['sessions'].values():
        item['expires_at'] = time.time() - 1
    assert lookup_session(state, session['token']) is None
    session = create_session(state, user)
    revoke_session(state, session['token'])
    assert lookup_session(state, session['token']) is None
