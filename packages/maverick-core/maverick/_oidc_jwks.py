"""Bounded public-key resolvers; never cache principals or authorization."""
from __future__ import annotations

import threading
import time
from collections import OrderedDict

FRESH_SECONDS = 300.0
REFRESH_COOLDOWN = 10.0
FETCH_TIMEOUT = 5.0
MAX_RESOLVERS = 16
MAX_KEYS = 128


class ResolverError(Exception):
    """No current signing key can safely be supplied."""


class Resolver:
    def __init__(self, jwt_mod, uri):
        # Unsupported old clients fail closed; never omit the network timeout.
        self.client = jwt_mod.PyJWKClient(uri, timeout=FETCH_TIMEOUT,
                                        cache_keys=False, cache_jwk_set=False)
        self.lock = threading.Lock()
        self.keys = ()
        self.expires = 0.0
        self.last_attempt = float("-inf")
        self.users = 0  # protected by the registry lock

    def key(self, kid):
        # One fetch per resolver even during concurrent cold starts/rotation.
        with self.lock:
            now = time.monotonic()
            fresh = now < self.expires
            if fresh:
                for key in self.keys:
                    if key.key_id == kid:
                        return key.key
            else:
                self.keys = ()  # expiry is a hard boundary, including outages
            if now < self.last_attempt + REFRESH_COOLDOWN:
                raise ResolverError("signing key refresh is temporarily unavailable")
            self.last_attempt = now
            keys = tuple(self.client.get_signing_keys(refresh=True))
            if not 1 <= len(keys) <= MAX_KEYS:
                raise ResolverError("invalid signing key set size")
            self.keys = keys
            self.expires = time.monotonic() + FRESH_SECONDS
            for key in keys:
                if key.key_id == kid:
                    return key.key
            # No attacker-controlled negative-kid cache: one refresh cooldown
            # bounds every unknown kid, regardless of how many distinct IDs arrive.
            raise ResolverError("signing key is unavailable")


_registry_lock = threading.Lock()
_resolvers: OrderedDict[tuple, Resolver] = OrderedDict()


def resolve(jwt_mod, token, config):
    header = jwt_mod.get_unverified_header(token)
    kid = header.get("kid")
    if not isinstance(kid, str) or not 1 <= len(kid) <= 256 or not kid.isprintable():
        raise ResolverError("invalid signing key identifier")
    if header.get("alg") not in config.algorithms:
        raise ResolverError("unaccepted signing algorithm")
    # A change to any verification policy selects a new resolver. Public keys
    # can be shared for an identical policy, but token claims are never cached.
    identity = (config.issuer, config.jwks_uri, config.audience, tuple(config.algorithms))
    with _registry_lock:
        resolver = _resolvers.get(identity)
        if resolver is None:
            if len(_resolvers) >= MAX_RESOLVERS:
                victim = next((key for key, value in _resolvers.items() if not value.users), None)
                if victim is None:
                    raise ResolverError("signing key resolver capacity is busy")
                del _resolvers[victim]
            resolver = Resolver(jwt_mod, config.jwks_uri)
            _resolvers[identity] = resolver
        _resolvers.move_to_end(identity)
        resolver.users += 1
    try:
        return resolver.key(kid)
    finally:
        with _registry_lock:
            resolver.users -= 1
