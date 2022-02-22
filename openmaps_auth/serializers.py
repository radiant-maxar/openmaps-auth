from io import BytesIO
import logging
import pickle

from pymemcache import serde
from rubymarshal import reader, writer


logger = logging.getLogger(__name__)


class RubyHash(dict):
    pass


def python_ruby_memcache_serializer(key, value):
    flags = 0
    value_type = type(value)

    # Check against exact types so that subclasses of native types will be
    # restored as their native type
    if value_type is bytes:
        pass

    elif value_type is RubyHash:
        value = writer.writes(value)

    elif value_type is str:
        flags |= serde.FLAG_TEXT
        value = value.encode("utf8")

    elif value_type is int:
        flags |= serde.FLAG_INTEGER
        value = "%d" % value

    else:
        flags |= serde.FLAG_PICKLE
        output = BytesIO()
        pickler = pickle.Pickler(output, serde.DEFAULT_PICKLE_VERSION)
        pickler.dump(value)
        value = output.getvalue()

    return value, flags


def python_ruby_memcache_deserializer(key, value, flags):
    if flags == 0:
        return value

    elif flags & serde.FLAG_TEXT:
        return value.decode("utf8")

    elif flags & serde.FLAG_INTEGER:
        return int(value)

    elif flags & serde.FLAG_LONG:
        return int(value)

    elif flags & serde.FLAG_PICKLE:
        try:
            if value[:2] == b"\x04\x08":
                return reader.loads(value)
            else:
                buf = BytesIO(value)
                unpickler = pickle.Unpickler(buf)
                return unpickler.load()
        except Exception:
            logger.info("Pickle error", exc_info=True)
            return None

    return value


class OpenMapsSerde:
    def __init__(self):
        self._serialize_func = python_ruby_memcache_serializer

    def serialize(self, key, value):
        return self._serialize_func(key, value)

    def deserialize(self, key, value, flags):
        return python_ruby_memcache_deserializer(key, value, flags)


openmaps_serde = OpenMapsSerde()
