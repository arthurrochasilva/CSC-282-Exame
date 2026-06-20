import sys
import types

try:
    import aiopg
except ModuleNotFoundError:
    class Connection:
        pass

    aiopg = types.ModuleType("aiopg")
    connection = types.ModuleType("aiopg.connection")
    aiopg.Connection = Connection
    aiopg.connection = connection
    connection.Connection = Connection
    sys.modules["aiopg"] = aiopg
    sys.modules["aiopg.connection"] = connection
