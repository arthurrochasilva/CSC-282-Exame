import asyncio

from sqli.dao.user import User

PASSWORD = "s3cret"
BCRYPT_HASH = "$2b$12$FVhFL/LLvehgDUhSyssrPe5lEz5032kz7rcbbMiyc8ol5cp.BqASC"


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def make_user(pwd_hash):
    return User(1, "Ada", None, "Lovelace", "ada", pwd_hash, False)


class FakeCursor:
    def __init__(self):
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, query, params=None):
        self.calls.append((query, params))


class FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor
