#!/usr/bin/env python3
"""
=============================================================================
 KEY MANAGER  —  Groq API Key Rotation (up to 10 keys)
=============================================================================
 When a key hits its rate limit (HTTP 429) the manager automatically
 rotates to the next available key.  Up to 10 keys are supported.

 Usage:
     from key_manager import KeyManager

     km = KeyManager([
         "gsk_key1...",
         "gsk_key2...",
         "gsk_key3...",
     ])

     # Use in CorrelationAgent / NarrativeGenerator:
     key = km.current_key()
     client = Groq(api_key=key)
     ...
     # When you hit 429:
     key = km.rotate()          # returns next key (None if all exhausted)

     # Or use the convenience wrapper:
     response = km.call_with_rotation(your_callable, *args, **kwargs)

 Integration:
     CorrelationAgent, all three domain agents, and evaluate_correlation.py
     all accept a `groq_api_key` parameter.  Pass km.current_key() there,
     and let km.rotate() handle 429s.
=============================================================================
"""

import time
import logging
from typing import Optional, List, Callable, Any

logger = logging.getLogger("KeyManager")


class KeyManager:
    """
    Rotates through up to 10 Groq API keys on rate-limit errors.

    Parameters
    ----------
    keys        : list of API key strings (1–10 keys)
    cooldown_s  : seconds to wait before re-trying a cooled-down key
                  (default 60 s; Groq rate-limit windows are 60 s)
    """

    MAX_KEYS = 10

    def __init__(self, keys: List[str], cooldown_s: int = 60):
        # Deduplicate and cap at MAX_KEYS
        seen = []
        for k in keys:
            k = k.strip()
            if k and k not in seen:
                seen.append(k)
        if not seen:
            raise ValueError("KeyManager requires at least one API key.")
        if len(seen) > self.MAX_KEYS:
            logger.warning(f"More than {self.MAX_KEYS} keys provided — using first {self.MAX_KEYS}.")
            seen = seen[:self.MAX_KEYS]

        self._keys:      List[str]           = seen
        self._cooldown:  int                 = cooldown_s
        self._index:     int                 = 0          # current key index
        self._exhausted: dict                = {}         # key → timestamp when exhausted
        self._usage:     dict                = {k: 0 for k in seen}   # call counts

        logger.info(f"KeyManager ready: {len(self._keys)} key(s) loaded")

    # ─────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────

    def current_key(self) -> Optional[str]:
        """Return the currently active key, or None if all are exhausted."""
        self._recover_cooled_keys()
        key = self._keys[self._index]
        if key in self._exhausted:
            # Try to find a fresh one
            return self.rotate()
        return key

    def rotate(self) -> Optional[str]:
        """
        Mark the current key as rate-limited and move to the next.
        Returns the new active key, or None if all keys are exhausted.
        """
        current = self._keys[self._index]
        self._exhausted[current] = time.time()
        logger.warning(
            f"Key #{self._index + 1} ({current[:12]}…) rate-limited. "
            f"Cooling down for {self._cooldown}s."
        )

        self._recover_cooled_keys()

        # Find next available key
        for i in range(len(self._keys)):
            next_idx = (self._index + 1 + i) % len(self._keys)
            candidate = self._keys[next_idx]
            if candidate not in self._exhausted:
                self._index = next_idx
                logger.info(
                    f"Rotated to key #{next_idx + 1} ({candidate[:12]}…)"
                )
                return candidate

        logger.error("All API keys are currently rate-limited.")
        return None

    def call_with_rotation(
        self,
        fn: Callable,
        *args,
        max_attempts: int = None,
        retry_delay_s: float = 2.0,
        **kwargs,
    ) -> Any:
        """
        Call ``fn(*args, **kwargs)`` using the current key.
        Automatically rotates the key on 429 / rate_limit errors and retries.

        The callable should accept a ``api_key`` keyword argument OR
        you can pass the key as part of *args — just ensure fn uses
        self.current_key() as described below.

        Simpler pattern: inject key each time via a lambda:

            result = km.call_with_rotation(
                lambda key: groq.Groq(api_key=key).chat.completions.create(...)
            )

        Parameters
        ----------
        fn            : callable that accepts no extra args (bind args first)
        max_attempts  : maximum total attempts (default = n_keys × 3)
        retry_delay_s : seconds to sleep between retries (non-rate-limit errors)
        """
        if max_attempts is None:
            max_attempts = len(self._keys) * 3

        last_error = None
        for attempt in range(max_attempts):
            key = self.current_key()
            if key is None:
                # All keys exhausted — wait for cooldown and try again once
                wait = self._cooldown
                logger.warning(f"All keys exhausted — sleeping {wait}s before last retry…")
                time.sleep(wait)
                self._exhausted.clear()   # reset after full cooldown
                key = self._keys[0]
                self._index = 0

            try:
                result = fn(key, *args, **kwargs)
                self._usage[key] = self._usage.get(key, 0) + 1
                return result

            except Exception as exc:
                last_error = exc
                err_str = str(exc).lower()

                if "429" in str(exc) or "rate_limit" in err_str or "rate limit" in err_str:
                    new_key = self.rotate()
                    if new_key:
                        logger.info(f"Retrying with new key (attempt {attempt + 2}/{max_attempts})…")
                        time.sleep(1.5)
                        continue
                    else:
                        # All keys exhausted — wait full cooldown
                        logger.warning(f"All keys exhausted, sleeping {self._cooldown}s…")
                        time.sleep(self._cooldown)
                        self._exhausted.clear()
                        self._index = 0
                        continue
                else:
                    # Non-rate-limit error — retry with same key after short delay
                    logger.warning(
                        f"API error (attempt {attempt + 1}/{max_attempts}): "
                        f"{str(exc)[:120]}"
                    )
                    time.sleep(retry_delay_s * (attempt + 1))
                    continue

        raise RuntimeError(
            f"All {max_attempts} attempts failed. Last error: {last_error}"
        )

    def status(self) -> dict:
        """Return current key pool status (useful for debugging)."""
        self._recover_cooled_keys()
        now = time.time()
        pool = []
        for i, k in enumerate(self._keys):
            if k in self._exhausted:
                remaining = max(0, self._cooldown - (now - self._exhausted[k]))
                state = f"COOLING ({remaining:.0f}s left)"
            elif i == self._index:
                state = "ACTIVE"
            else:
                state = "READY"
            pool.append({
                "index":  i + 1,
                "key":    k[:12] + "…",
                "state":  state,
                "calls":  self._usage.get(k, 0),
            })
        return {
            "total_keys":       len(self._keys),
            "active_key_index": self._index + 1,
            "keys":             pool,
        }

    # ─────────────────────────────────────────────────────────────────
    # Internal helpers
    # ─────────────────────────────────────────────────────────────────

    def _recover_cooled_keys(self):
        """Move keys whose cooldown period has elapsed back to available."""
        now = time.time()
        recovered = [
            k for k, t in self._exhausted.items()
            if (now - t) >= self._cooldown
        ]
        for k in recovered:
            del self._exhausted[k]
            logger.info(f"Key {k[:12]}… cooldown elapsed — back in pool.")


# ─────────────────────────────────────────────────────────────────────────────
# Convenience: build KeyManager from comma-separated env var or a list
# ─────────────────────────────────────────────────────────────────────────────

def build_key_manager(keys_input) -> Optional["KeyManager"]:
    """
    Build a KeyManager from:
      - a list of key strings
      - a single key string
      - a comma-separated string of keys
      - None (returns None)

    Examples
    --------
    km = build_key_manager("gsk_key1,gsk_key2,gsk_key3")
    km = build_key_manager(["gsk_key1", "gsk_key2"])
    km = build_key_manager(os.environ.get("GROQ_API_KEYS", ""))
    """
    if not keys_input:
        return None
    if isinstance(keys_input, str):
        keys = [k.strip() for k in keys_input.split(",") if k.strip()]
    elif isinstance(keys_input, (list, tuple)):
        keys = [k.strip() for k in keys_input if k and k.strip()]
    else:
        return None

    if not keys:
        return None
    return KeyManager(keys)
