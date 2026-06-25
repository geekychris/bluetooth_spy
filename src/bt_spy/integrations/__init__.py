"""Integration generators: standalone driver, Home Assistant component, MQTT bridge.

Everything here is downstream of `protocol_entries`. The contract: if you name
your protocol entries from the canonical vocabulary in `vocabulary.py`, you get
a working HA integration scaffolded for free. Names outside the vocabulary are
still exported on the driver but won't be wired into HA entities — you'd add
those by hand (or push the vocabulary to add the new mapping).
"""
