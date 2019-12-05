from django.apps import AppConfig


class MainConfig(AppConfig):
    name = 'main'
try:
    from collections.abc import defaultdict, Mapping, namedtuple
except ImportError:
    from collections import defaultdict, Mapping, namedtuple