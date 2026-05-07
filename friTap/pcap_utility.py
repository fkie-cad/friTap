#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Filename-extension helper. Extension wins over output_format so a user
who writes ``test.pcap`` always gets classic libpcap, even if an earlier
code path set ``output_format='pcapng'``."""


def is_pcapng_filename(name):
    """Return True iff `name` has a .pcapng extension (case-insensitive)."""
    return bool(name) and name.lower().endswith(".pcapng")
