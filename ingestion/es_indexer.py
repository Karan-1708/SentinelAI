"""
Elasticsearch async bulk indexer for CICIDS-2017 records.

Uses the elasticsearch-py 8.x async client with async_bulk helper.
chunk_size=500 balances throughput vs memory for the 2.8M-row dataset.
"""

from __future__ import annotations

import logging
from typing import AsyncIterator

import pandas as pd
from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

logger = logging.getLogger(__name__)


def _make_actions(
    records: list[dict],
    index: str,
) -> AsyncIterator[dict]:
    """Yield Elasticsearch bulk action dicts from a list of records."""
    for record in records:
        yield {"_index": index, "_source": record}


async def bulk_index(
    client: AsyncElasticsearch,
    records: list[dict],
    index: str,
    chunk_size: int = 500,
) -> tuple[int, list[dict]]:
    """
    Bulk-index records into Elasticsearch.
    Returns (success_count, failed_items).
    """
    successes, errors = await async_bulk(
        client,
        _make_actions(records, index),
        chunk_size=chunk_size,
        raise_on_error=False,
        raise_on_exception=False,
    )
    if errors:
        logger.warning("Bulk index: %d errors out of %d records", len(errors), len(records))
    return successes, errors


async def index_dataframe(
    client: AsyncElasticsearch,
    df: pd.DataFrame,
    index: str,
    chunk_size: int = 500,
) -> int:
    """
    Index an entire DataFrame into Elasticsearch.
    Converts NaN to None (JSON null) before indexing.
    Returns total number of successfully indexed documents.
    """
    total_success = 0
    records = df.where(pd.notna(df), None).to_dict(orient="records")

    # Process in chunks to avoid holding the entire dataset in memory as a list of dicts
    for start in range(0, len(records), chunk_size * 10):
        batch = records[start : start + chunk_size * 10]
        success, _ = await bulk_index(client, batch, index, chunk_size=chunk_size)
        total_success += success
        logger.info("Indexed %d / %d documents into %s", total_success, len(records), index)

    return total_success


def get_client(
    hosts: list[str],
    username: str,
    password: str,
    ca_certs: str | None = None,
    verify_certs: bool = True,
) -> AsyncElasticsearch:
    """Create and return an authenticated async Elasticsearch client."""
    return AsyncElasticsearch(
        hosts=hosts,
        basic_auth=(username, password),
        ca_certs=ca_certs,
        verify_certs=verify_certs,
        ssl_show_warn=False,
    )
