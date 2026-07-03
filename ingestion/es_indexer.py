"""
Elasticsearch async bulk indexer for CICIDS-2017 records.

Uses the elasticsearch-py 8.x async client with the async_bulk helper.
chunk_size=500 balances throughput vs memory for the 2.8M-row dataset.

Failure model:
  * ``async_bulk`` runs with ``raise_on_error=False`` because a single bad
    document should not abort a 500-doc batch.
  * The caller receives the failed items back and *must* handle them
    (log to a dead-letter file, retry, or fail the pipeline). Silent-drop
    of failures is unacceptable in a threat-detection pipeline.
"""

from __future__ import annotations

import logging
from typing import AsyncIterator

import pandas as pd
from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

logger = logging.getLogger(__name__)


class BulkIndexError(RuntimeError):
    """Raised when ingestion has any failed documents and ``strict=True``."""

    def __init__(self, failed: list[dict]):
        super().__init__(f"{len(failed)} document(s) failed to index")
        self.failed = failed


def _make_actions(records: list[dict], index: str) -> AsyncIterator[dict]:
    for record in records:
        yield {"_index": index, "_source": record}


async def bulk_index(
    client: AsyncElasticsearch,
    records: list[dict],
    index: str,
    chunk_size: int = 500,
    *,
    strict: bool = False,
) -> tuple[int, list[dict]]:
    """
    Bulk-index records into Elasticsearch.

    Returns ``(success_count, failed_items)``. Callers must inspect
    ``failed_items`` — passing ``strict=True`` raises ``BulkIndexError``
    instead so a batch cannot fail silently.
    """
    successes, errors = await async_bulk(
        client,
        _make_actions(records, index),
        chunk_size=chunk_size,
        raise_on_error=False,
        raise_on_exception=False,
    )
    if errors:
        logger.error("Bulk index: %d errors out of %d records", len(errors), len(records))
        if strict:
            raise BulkIndexError(errors)
    return successes, errors


async def index_dataframe(
    client: AsyncElasticsearch,
    df: pd.DataFrame,
    index: str,
    chunk_size: int = 500,
    *,
    strict: bool = False,
) -> tuple[int, int]:
    """
    Index an entire DataFrame into Elasticsearch.

    Converts NaN to ``None`` (JSON null) before indexing. Returns
    ``(total_success, total_failed)`` so the caller can decide what to do
    with a partially-successful batch.
    """
    total_success = 0
    total_failed = 0
    records = df.where(pd.notna(df), None).to_dict(orient="records")

    for start in range(0, len(records), chunk_size):
        batch = records[start : start + chunk_size]
        success, failed = await bulk_index(
            client, batch, index, chunk_size=chunk_size, strict=strict
        )
        total_success += success
        total_failed += len(failed)
        logger.info(
            "Indexed %d/%d documents into %s (failed=%d)",
            total_success,
            len(records),
            index,
            total_failed,
        )

    return total_success, total_failed


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
