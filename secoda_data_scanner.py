#!/usr/bin/env python3
"""
Interactive Secoda data compliance scanner.

What it does:
1) Pulls databases, schemas, tables, and columns from the Secoda catalog API.
2) Fetches table previews and extracts sample values for each column.
3) Asks Gemini to classify unmarked columns for PII/PCI/PHI risk.
4) Writes JSON/CSV reports with a review_pii column for human review.
5) Pauses until the CSV is reviewed, then marks reviewed PII columns in Secoda.
"""

from __future__ import annotations

import csv
import getpass
import hashlib
import json
import re
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request

DEFAULT_BASE_URL = "https://app.secoda.co/api/v1"
STATE_FILE = Path(".secoda_pii_scan_state.json")
REPORT_PREFIX = "secoda_pii_report"
MAX_TABLES_PER_AI_PROMPT = 15
DEFAULT_PAGE_SIZE = 1000
DEFAULT_GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"
DEFAULT_SCAN_FOR = "pii"
SUPPORTED_SCAN_TYPES = ("PII", "PCI", "PHI")

# Optional local testing overrides. Leave these blank for interactive prompts.
# Do not commit real API keys.
HARDCODED_API_KEY = ""
HARDCODED_DATABASES = ""
HARDCODED_SCHEMAS = ""
HARDCODED_GEMINI_API_KEY = ""
HARDCODED_GEMINI_MODEL = ""
HARDCODED_SINGLE_TABLE = ""


class SecodaApiError(RuntimeError):
    pass


class GeminiApiError(RuntimeError):
    pass


@dataclass
class TableScanSpec:
    database: str
    schema: str
    table: str
    unmarked_columns: list[str]
    already_pii_columns: list[str]

    @property
    def table_key(self) -> str:
        return canonical_table_key(self.database, self.schema, self.table)


@dataclass
class CatalogResource:
    id: str
    title: str
    title_full: str
    entity_type: str
    parent_id: str
    pii: bool
    raw: dict[str, Any]


@dataclass
class TableInventory:
    database: CatalogResource
    schema: CatalogResource
    table: CatalogResource
    columns: list[CatalogResource]


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_name(value: str) -> str:
    return value.strip().strip('"').strip("'").strip("`")


def resource_string(resource: dict[str, Any], key: str) -> str:
    value = resource.get(key)
    if value is None:
        return ""
    return canonical_name(str(value))


def resource_parent_id(resource: dict[str, Any]) -> str:
    parent = resource.get("parent_id") or resource.get("parent")
    if parent is None:
        return ""
    return str(parent)


def to_catalog_resource(resource: dict[str, Any]) -> CatalogResource | None:
    resource_id = resource.get("id")
    if not resource_id:
        return None

    return CatalogResource(
        id=str(resource_id),
        title=resource_string(resource, "title"),
        title_full=resource_string(resource, "title_full"),
        entity_type=resource_string(resource, "entity_type"),
        parent_id=resource_parent_id(resource),
        pii=to_bool(resource.get("pii")),
        raw=resource,
    )


def canonical_table_key(database: str, schema: str, table: str) -> str:
    return ".".join(
        [
            canonical_name(database).lower(),
            canonical_name(schema).lower(),
            canonical_name(table).lower(),
        ]
    )


def filter_label(values: set[str]) -> str:
    if not values:
        return "all"
    return ", ".join(sorted(values))


def response_next_page(response: dict[str, Any]) -> int | None:
    next_page = response.get("meta", {}).get("next_page")
    if next_page is None:
        next_url = response.get("links", {}).get("next")
        if isinstance(next_url, str) and next_url:
            parsed = parse.urlparse(next_url)
            page_values = parse.parse_qs(parsed.query).get("page")
            if page_values:
                next_page = page_values[0]
    if next_page is None:
        return None
    try:
        return int(next_page)
    except (TypeError, ValueError):
        return None


def to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    return False


def prompt_input(
    message: str, *, default: str | None = None, secret: bool = False
) -> str:
    suffix = f" [{default}]" if default else ""
    prompt = f"{message}{suffix}: "
    while True:
        raw = getpass.getpass(prompt) if secret else input(prompt)
        value = raw.strip()
        if value:
            return value
        if default is not None:
            return default
        print("This value is required.")


def prompt_optional_csv(message: str) -> set[str]:
    raw = input(f"{message} (comma separated, blank for all): ").strip()
    return csv_filter_values(raw)


def prompt_optional_input(message: str, *, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{message}{suffix}: ").strip()
    if raw:
        return raw
    return default


def prompt_scan_types(default_value: str = DEFAULT_SCAN_FOR) -> list[str]:
    raw = input(
        "Compliance categories to scan "
        f"(comma separated: {', '.join(SUPPORTED_SCAN_TYPES)}) [{default_value}]: "
    ).strip()
    selected = raw or default_value
    return parse_scan_types(selected)


def csv_filter_values(raw: str) -> set[str]:
    if not raw:
        return set()
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def parse_scan_types(raw: str) -> list[str]:
    values = [item.strip().upper() for item in raw.split(",") if item.strip()]
    if not values:
        raise ValueError(
            f"At least one scan category is required: {', '.join(SUPPORTED_SCAN_TYPES)}"
        )
    deduped = sorted(set(values))
    unsupported = [value for value in deduped if value not in SUPPORTED_SCAN_TYPES]
    if unsupported:
        raise ValueError(
            f"Unsupported scan category: {', '.join(unsupported)}. "
            f"Supported values: {', '.join(SUPPORTED_SCAN_TYPES)}"
        )
    return deduped


def parse_scan_types_loose(raw: str) -> list[str]:
    return [
        item.strip().upper()
        for item in raw.split(",")
        if item.strip() and item.strip().upper() in SUPPORTED_SCAN_TYPES
    ]


def prompt_yes_no(message: str, *, default_yes: bool = True) -> bool:
    default_label = "Y/n" if default_yes else "y/N"
    while True:
        value = input(f"{message} [{default_label}]: ").strip().lower()
        if not value:
            return default_yes
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("Please answer yes or no.")


class SecodaClient:
    def __init__(self, base_url: str, api_key: str, timeout_seconds: int = 60) -> None:
        normalized_base_url = base_url.rstrip("/")
        if not normalized_base_url.endswith("/api/v1"):
            normalized_base_url = f"{normalized_base_url}/api/v1"
        self.base_url = normalized_base_url
        self.api_key = self._normalize_api_key(api_key)
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _normalize_api_key(api_key: str) -> str:
        token = api_key.strip().strip('"').strip("'")
        if token.lower().startswith("authorization:"):
            token = token.split(":", 1)[1].strip()
        if token.lower().startswith("bearer "):
            token = token.split(None, 1)[1].strip()
        return token

    def _url(self, path: str, query: str = "") -> str:
        if path.startswith("/api/v1/"):
            path = path.removeprefix("/api/v1")
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{self.base_url}{path}{query}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        payload: Any | None = None,
    ) -> dict[str, Any]:
        query = ""
        if params:
            normalized: dict[str, str] = {}
            for key, value in params.items():
                if value is None:
                    continue
                normalized[key] = value if isinstance(value, str) else str(value)
            query = "?" + parse.urlencode(normalized)

        url = self._url(path, query)
        data = None
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "User-Agent": "SecodaPIIScanner/1.0",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = request.Request(url=url, method=method, headers=headers, data=data)
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = resp.read().decode("utf-8")
                if not body:
                    return {}
                return json.loads(body)
        except error.HTTPError as exc:
            detail = ""
            detail = exc.fp.read().decode("utf-8", errors="replace")
            raise SecodaApiError(
                f"HTTP {exc.code} on {path}: {detail or exc.reason}"
            ) from exc
        except error.URLError as exc:
            raise SecodaApiError(f"Network error on {path}: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise SecodaApiError(f"Invalid JSON response from {path}") from exc

    def _fetch_columns_page(
        self, page: int, page_size: int = DEFAULT_PAGE_SIZE
    ) -> tuple[int, list[dict[str, Any]], dict[str, Any]]:
        response = self._request(
            "GET",
            "/table/columns/",
            params={
                "page": page,
                "page_size": page_size,
                "disable_sorting": True,
            },
        )
        results = response.get("results", [])
        if not isinstance(results, list):
            raise SecodaApiError(
                "Unexpected columns response: 'results' is not a list."
            )
        return page, results, response

    def fetch_columns_page(
        self, page: int, page_size: int = DEFAULT_PAGE_SIZE
    ) -> tuple[int, list[dict[str, Any]], dict[str, Any]]:
        return self._fetch_columns_page(page, page_size)

    def list_columns(self, max_workers: int = 8) -> list[dict[str, Any]]:
        print("  Fetching page 1...", end=" ", flush=True)
        _, first_results, first_response = self._fetch_columns_page(1)
        total_pages = (
            first_response.get("total_pages")
            or first_response.get("meta", {}).get("total_pages")
            or 1
        )
        try:
            total_pages = max(1, int(total_pages))
        except (TypeError, ValueError):
            total_pages = 1
        print(f"({len(first_results)} columns, page 1/{total_pages})")

        all_results: list[dict[str, Any]] = list(first_results)

        if str(first_response.get("count")) == "999999":
            print(
                "  Count timed out on the API; fetching remaining pages sequentially."
            )
            next_page = response_next_page(first_response)
            while next_page:
                page_num, results, page_response = self._fetch_columns_page(next_page)
                if not results:
                    print(f"  Stopping at empty page {page_num}.")
                    break
                all_results.extend(results)
                print(f"  Fetched page {page_num} ({len(results)} columns)")
                next_page = response_next_page(page_response)
            print(f"  Done. Fetched {len(all_results)} column(s) total.")
            return all_results

        if total_pages > 1:
            remaining_pages = range(2, total_pages + 1)
            page_results: dict[int, list[dict[str, Any]]] = {}

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._fetch_columns_page, p): p
                    for p in remaining_pages
                }
                for future in as_completed(futures):
                    page_num, results, _ = future.result()
                    page_results[page_num] = results
                    print(
                        f"  Fetched page {page_num}/{total_pages} ({len(results)} columns)",
                        flush=True,
                    )

            for p in sorted(page_results):
                all_results.extend(page_results[p])

        print(f"  Done. Fetched {len(all_results)} column(s) total.")
        return all_results

    def _fetch_catalog_page(
        self,
        page: int,
        *,
        entity_type: str,
        parent_id: str | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> tuple[int, list[dict[str, Any]], dict[str, Any]]:
        filters: list[dict[str, Any]] = []
        if parent_id:
            filters.append(
                {
                    "operands": [],
                    "field": "parent_id",
                    "operator": "exact",
                    "value": parent_id,
                }
            )

        response = self._request(
            "GET",
            "/resource/catalog/",
            params={
                "page": page,
                "page_size": page_size,
                "calculate_children_count": "true",
                "entity_type": entity_type,
                "filter": json.dumps(
                    {"operator": "and", "operands": filters},
                    separators=(",", ":"),
                )
                if filters
                else None,
                "search_term": "",
                "sort": json.dumps(
                    {"field": "sort_order", "order": "asc"},
                    separators=(",", ":"),
                ),
            },
        )
        results = response.get("results", [])
        if not isinstance(results, list):
            raise SecodaApiError(
                "Unexpected catalog response: 'results' is not a list."
            )
        return page, results, response

    def fetch_catalog_page(
        self,
        page: int,
        *,
        entity_type: str,
        parent_id: str | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> tuple[int, list[dict[str, Any]], dict[str, Any]]:
        return self._fetch_catalog_page(
            page,
            entity_type=entity_type,
            parent_id=parent_id,
            page_size=page_size,
        )

    def list_catalog_resources(
        self,
        entity_type: str,
        *,
        parent_id: str | None = None,
    ) -> list[CatalogResource]:
        parent_label = f" parent={parent_id}" if parent_id else ""
        print(
            f"      Fetching {entity_type} resources{parent_label} page 1...",
            flush=True,
        )
        _, first_results, first_response = self._fetch_catalog_page(
            1,
            entity_type=entity_type,
            parent_id=parent_id,
        )
        all_results = list(first_results)

        total_pages = (
            first_response.get("total_pages")
            or first_response.get("meta", {}).get("total_pages")
            or 1
        )
        try:
            total_pages = max(1, int(total_pages))
        except (TypeError, ValueError):
            total_pages = 1
        print(
            f"      Fetched {len(first_results)} {entity_type} item(s) on page 1/{total_pages}.",
            flush=True,
        )

        next_page = response_next_page(first_response)
        while next_page:
            page_num, results, page_response = self._fetch_catalog_page(
                next_page,
                entity_type=entity_type,
                parent_id=parent_id,
            )
            if not results:
                break
            all_results.extend(results)
            print(
                f"      Fetched {entity_type} page {page_num}/{total_pages} ({len(results)} item(s))",
                flush=True,
            )
            next_page = response_next_page(page_response)

        if not next_page and total_pages > 1 and len(all_results) == len(first_results):
            for page in range(2, total_pages + 1):
                page_num, results, _ = self._fetch_catalog_page(
                    page,
                    entity_type=entity_type,
                    parent_id=parent_id,
                )
                all_results.extend(results)
                print(
                    f"      Fetched {entity_type} page {page_num}/{total_pages} ({len(results)} item(s))",
                    flush=True,
                )

        resources = [to_catalog_resource(item) for item in all_results]
        return [resource for resource in resources if resource is not None]

    def get_table_preview(self, table_id: str) -> dict[str, Any]:
        return self._request("GET", f"/resource/preview_v2/table/{table_id}/")

    def get_resource(self, resource_id: str) -> dict[str, Any]:
        return self._request("GET", f"/resource/all/{resource_id}")

    def bulk_update_resources(self, payload: list[dict[str, Any]]) -> list[Any]:
        response = self._request("POST", "/resource/all/bulk_update/", payload=payload)
        if isinstance(response, list):
            return response
        if isinstance(response.get("results"), list):
            return response["results"]
        return [response]

    def list_tags(self) -> list[dict[str, Any]]:
        page = 1
        tags: list[dict[str, Any]] = []
        while True:
            response = self._request(
                "GET",
                "/tag",
                params={"page": page, "page_size": DEFAULT_PAGE_SIZE},
            )
            results = response.get("results", [])
            if not isinstance(results, list):
                raise SecodaApiError("Unexpected tags response: 'results' is not a list.")
            tags.extend([tag for tag in results if isinstance(tag, dict)])
            next_page = response_next_page(response)
            if next_page is None:
                break
            page = next_page
        return tags

    def create_tag(
        self,
        *,
        name: str,
        color: str = "#4299E1",
        description: str = "Created by Secoda PII Scanner",
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            "/tag",
            payload={
                "name": name,
                "color": color,
                "description": description,
            },
        )
        if not isinstance(response, dict):
            raise SecodaApiError("Unexpected create-tag response shape.")
        return response


class GeminiClient:
    def __init__(
        self,
        api_key: str,
        *,
        model: str = DEFAULT_GEMINI_MODEL,
        base_url: str = DEFAULT_GEMINI_API_URL,
        timeout_seconds: int = 120,
    ) -> None:
        self.api_key = api_key.strip().strip('"').strip("'")
        self.model = model.strip() or DEFAULT_GEMINI_MODEL
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def generate_json(self, prompt_text: str) -> dict[str, Any]:
        if not self.api_key:
            raise GeminiApiError("Gemini API key is required.")

        model_path = parse.quote(self.model, safe="")
        url = f"{self.base_url}/models/{model_path}:generateContent"
        query = "?" + parse.urlencode({"key": self.api_key})
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt_text}],
                }
            ],
            "generationConfig": {
                "temperature": 0,
                "responseMimeType": "application/json",
            },
        }
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "SecodaPIIScanner/1.0",
        }
        req = request.Request(
            url=f"{url}{query}",
            method="POST",
            headers=headers,
            data=data,
        )

        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = resp.read().decode("utf-8")
        except error.HTTPError as exc:
            detail = exc.fp.read().decode("utf-8", errors="replace")
            raise GeminiApiError(
                f"Gemini HTTP {exc.code} for model {self.model}: {detail or exc.reason}"
            ) from exc
        except error.URLError as exc:
            raise GeminiApiError(f"Gemini network error: {exc.reason}") from exc

        try:
            response = json.loads(body)
        except json.JSONDecodeError as exc:
            raise GeminiApiError("Gemini returned invalid JSON.") from exc

        response_text = self._response_text(response)
        if not response_text:
            raise GeminiApiError(f"Gemini response did not include text: {response}")
        try:
            return extract_json_from_text(response_text)
        except SecodaApiError as exc:
            raise GeminiApiError(
                "Could not parse valid JSON from Gemini response."
            ) from exc

    @staticmethod
    def _response_text(response: dict[str, Any]) -> str:
        candidates = response.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            return ""

        first_candidate = candidates[0]
        if not isinstance(first_candidate, dict):
            return ""

        content = first_candidate.get("content")
        if not isinstance(content, dict):
            return ""

        parts = content.get("parts")
        if not isinstance(parts, list):
            return ""

        text_parts = [
            str(part.get("text", ""))
            for part in parts
            if isinstance(part, dict) and part.get("text")
        ]
        return "\n".join(text_parts).strip()


def derive_location(column_resource: dict[str, Any]) -> tuple[str, str, str, str]:
    column_name = resource_string(column_resource, "title")
    db = resource_string(column_resource, "table_database")
    schema = resource_string(column_resource, "table_schema")
    table = resource_string(column_resource, "table_title")

    title_full = str(column_resource.get("title_full", "")).strip()
    if (not db or not schema or not table) and title_full:
        parts = [canonical_name(p) for p in title_full.split(".") if p.strip()]
        if len(parts) >= 4:
            if not column_name:
                column_name = parts[-1]
            if not table:
                table = parts[-2]
            if not schema:
                schema = parts[-3]
            if not db:
                db = ".".join(parts[:-3])

    return db, schema, table, column_name


def build_table_specs(
    column_resources: list[dict[str, Any]],
    *,
    database_filter: set[str],
    schema_filter: set[str],
) -> dict[str, TableScanSpec]:
    grouped: dict[str, TableScanSpec] = {}
    for item in column_resources:
        db, schema, table, column_name = derive_location(item)
        if not (db and schema and table and column_name):
            continue

        if database_filter and db.lower() not in database_filter:
            continue
        if schema_filter and schema.lower() not in schema_filter:
            continue

        key = canonical_table_key(db, schema, table)
        if key not in grouped:
            grouped[key] = TableScanSpec(
                database=db,
                schema=schema,
                table=table,
                unmarked_columns=[],
                already_pii_columns=[],
            )

        pii = to_bool(item.get("pii"))
        if pii:
            grouped[key].already_pii_columns.append(column_name)
        else:
            grouped[key].unmarked_columns.append(column_name)

    for spec in grouped.values():
        spec.unmarked_columns = sorted(set(spec.unmarked_columns), key=str.lower)
        spec.already_pii_columns = sorted(set(spec.already_pii_columns), key=str.lower)
    return grouped


def summarize_column_locations(
    columns: list[dict[str, Any]],
    *,
    database_filter: set[str],
    schema_filter: set[str],
    max_locations: int = 50,
) -> None:
    missing_location_count = 0
    matched_column_count = 0
    seen: dict[tuple[str, str], int] = {}

    for item in columns:
        db, schema, table, column_name = derive_location(item)
        if not (db and schema and table and column_name):
            missing_location_count += 1
            continue

        db_match = (not database_filter) or db.lower() in database_filter
        schema_match = (not schema_filter) or schema.lower() in schema_filter
        if db_match and schema_match:
            matched_column_count += 1

        key = (db, schema)
        seen[key] = seen.get(key, 0) + 1

    print(
        f"  Columns with complete location metadata: {len(columns) - missing_location_count}"
    )
    print(f"  Columns missing database/schema/table metadata: {missing_location_count}")
    print(
        f"  Columns matching selected database/schema filters: {matched_column_count}"
    )
    print("  Unique database/schema pairs:")
    for idx, ((db, schema), count) in enumerate(sorted(seen.items()), start=1):
        if idx > max_locations:
            remaining = len(seen) - max_locations
            print(f"    ... {remaining} more pair(s)")
            break
        db_match = (not database_filter) or db.lower() in database_filter
        schema_match = (not schema_filter) or schema.lower() in schema_filter
        match_str = (
            "MATCH"
            if db_match and schema_match
            else f"skip db={db_match} schema={schema_match}"
        )
        print(f"    {db!r} / {schema!r}: {count} column(s) [{match_str}]")


def table_fingerprint(spec: TableScanSpec) -> str:
    raw = {
        "database": spec.database.lower(),
        "schema": spec.schema.lower(),
        "table": spec.table.lower(),
        "unmarked_columns": sorted([c.lower() for c in spec.unmarked_columns]),
        "already_pii_columns": sorted([c.lower() for c in spec.already_pii_columns]),
    }
    return hashlib.sha256(json.dumps(raw, sort_keys=True).encode("utf-8")).hexdigest()


def load_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {"tables": {}}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"tables": {}}


def save_state(state: dict[str, Any]) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def chunked(items: list[TableScanSpec], size: int) -> list[list[TableScanSpec]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def extract_json_from_text(text: str) -> dict[str, Any]:
    content = text.strip()
    fenced = re.search(
        r"```(?:json)?\s*(\{.*?\})\s*```", content, flags=re.DOTALL | re.IGNORECASE
    )
    if fenced:
        content = fenced.group(1).strip()

    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    candidates = re.findall(r"\{[\s\S]*\}", text)
    for candidate in sorted(candidates, key=len, reverse=True):
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    raise SecodaApiError("Could not parse valid JSON from AI response.")


def csv_bool(value: bool) -> str:
    return "TRUE" if value else "FALSE"


def truncate_text(value: Any, max_length: int = 250) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3]}..."


def parse_tag_ids(value: Any) -> list[str]:
    def normalize_tag_id(tag_value: Any) -> str:
        if isinstance(tag_value, dict):
            tag_value = tag_value.get("id")
        if tag_value is None:
            return ""
        try:
            return str(uuid.UUID(str(tag_value)))
        except (ValueError, TypeError, AttributeError):
            return ""

    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            return parse_tag_ids(parsed)
        except json.JSONDecodeError:
            normalized = normalize_tag_id(text)
            return [normalized] if normalized else []
    if not isinstance(value, list):
        return []

    seen: set[str] = set()
    cleaned: list[str] = []
    for item in value:
        normalized = normalize_tag_id(item)
        if normalized and normalized not in seen:
            seen.add(normalized)
            cleaned.append(normalized)
    return cleaned


def append_tag_id(existing_tag_ids: list[str], tag_id_to_add: str | None) -> list[str]:
    if not tag_id_to_add:
        return existing_tag_ids
    merged = list(existing_tag_ids)
    if tag_id_to_add not in merged:
        merged.append(tag_id_to_add)
    return merged


def resolve_or_create_tag_id(client: SecodaClient, tag_name: str) -> tuple[str, bool]:
    normalized_name = canonical_name(tag_name)
    if not normalized_name:
        return "", False

    for tag in client.list_tags():
        existing_name = canonical_name(str(tag.get("name", "")))
        if existing_name.lower() == normalized_name.lower():
            tag_id = str(tag.get("id", "")).strip()
            try:
                return str(uuid.UUID(tag_id)), False
            except (ValueError, TypeError, AttributeError):
                continue

    created = client.create_tag(name=normalized_name)
    created_tag_id = str(created.get("id", "")).strip()
    try:
        return str(uuid.UUID(created_tag_id)), True
    except (ValueError, TypeError, AttributeError) as exc:
        raise SecodaApiError(
            f"Created tag '{normalized_name}' but response did not include a valid ID."
        ) from exc


def column_data_type(column: CatalogResource) -> str:
    metadata = column.raw.get("search_metadata")
    if isinstance(metadata, dict):
        for key in ("type", "data_type"):
            if metadata.get(key):
                return str(metadata[key])
    return resource_string(column.raw, "data_type")


def preview_column_samples(
    preview: dict[str, Any],
    column_name: str,
    *,
    max_samples: int = 10,
) -> list[str]:
    preview_columns = preview.get("columns", [])
    rows = preview.get("data", [])
    if not isinstance(preview_columns, list) or not isinstance(rows, list):
        return []

    normalized_column = canonical_name(column_name).lower()
    column_index: int | None = None
    for idx, preview_column in enumerate(preview_columns):
        if canonical_name(str(preview_column)).lower() == normalized_column:
            column_index = idx
            break

    samples: list[str] = []
    for row in rows:
        value: Any = None
        if isinstance(row, dict):
            value = row.get(column_name)
            if value is None:
                for key, row_value in row.items():
                    if canonical_name(str(key)).lower() == normalized_column:
                        value = row_value
                        break
        elif (
            isinstance(row, list)
            and column_index is not None
            and column_index < len(row)
        ):
            value = row[column_index]

        if value is None:
            continue

        sample = truncate_text(value)
        if sample and sample not in samples:
            samples.append(sample)
        if len(samples) >= max_samples:
            break

    return samples


def discover_table_inventory(
    client: SecodaClient,
    *,
    database_filter: set[str],
    schema_filter: set[str],
    single_table: str | None = None,
) -> list[TableInventory]:
    print("\nFetching databases from Secoda catalog...")
    databases = client.list_catalog_resources("database")
    print(f"  Found {len(databases)} database(s).")

    inventory: list[TableInventory] = []
    normalized_single_table = canonical_name(single_table or "").lower()
    for db_index, database in enumerate(databases, start=1):
        if database_filter and database.title.lower() not in database_filter:
            print(
                f"  [{db_index}/{len(databases)}] Skipping database: {database.title}"
            )
            continue

        print(f"  [{db_index}/{len(databases)}] Database: {database.title}")
        print(f"    Fetching schemas for database {database.title}...", flush=True)
        schemas = client.list_catalog_resources(
            "schema",
            parent_id=database.id,
        )
        print(f"    Found {len(schemas)} schema(s).")

        for schema_index, schema in enumerate(schemas, start=1):
            if schema_filter and schema.title.lower() not in schema_filter:
                print(
                    f"    [{schema_index}/{len(schemas)}] Skipping schema: {schema.title}"
                )
                continue

            print(f"    [{schema_index}/{len(schemas)}] Schema: {schema.title}")
            print(
                f"      Fetching tables for schema {database.title}.{schema.title}...",
                flush=True,
            )
            tables = client.list_catalog_resources(
                "table",
                parent_id=schema.id,
            )
            print(f"      Found {len(tables)} table(s).")

            for table_index, table in enumerate(tables, start=1):
                if (
                    normalized_single_table
                    and table.title.lower() != normalized_single_table
                ):
                    print(
                        f"      [{table_index}/{len(tables)}] Skipping table: {table.title}"
                    )
                    continue

                print(
                    f"      [{table_index}/{len(tables)}] Fetching columns for "
                    f"{database.title}.{schema.title}.{table.title}...",
                    flush=True,
                )
                columns = client.list_catalog_resources(
                    "column",
                    parent_id=table.id,
                )
                print(
                    f"      [{table_index}/{len(tables)}] Found {len(columns)} column(s) for "
                    f"{database.title}.{schema.title}.{table.title}.",
                    flush=True,
                )
                if columns:
                    inventory.append(
                        TableInventory(
                            database=database,
                            schema=schema,
                            table=table,
                            columns=columns,
                        )
                    )
                    if single_table is not None:
                        print("      Single-table test mode complete.")
                        return inventory

    return inventory


def preview_rows_for_prompt(
    preview: dict[str, Any], *, max_rows: int = 50
) -> list[Any]:
    rows = preview.get("data", [])
    if not isinstance(rows, list):
        return []

    prompt_rows: list[Any] = []
    for row in rows[:max_rows]:
        if isinstance(row, dict):
            prompt_rows.append(
                {
                    str(key): truncate_text(value, max_length=150)
                    for key, value in row.items()
                }
            )
        elif isinstance(row, list):
            prompt_rows.append([truncate_text(value, max_length=150) for value in row])
        else:
            prompt_rows.append(truncate_text(row, max_length=150))
    return prompt_rows


def build_table_ai_prompt(
    *,
    table_input: dict[str, Any],
    column_inputs: list[dict[str, Any]],
    preview: dict[str, Any],
    scan_types: list[str],
) -> str:
    scan_scope_instructions = {
        "PII": (
            "PII: personally identifiable information, such as names, personal emails, "
            "phone numbers, home addresses, government IDs, precise geolocation, or "
            "persistent user identifiers tied to a natural person."
        ),
        "PCI": (
            "PCI: payment card information, such as PAN/card numbers, CVV/CVC, card "
            "expiration dates, cardholder names tied to card data, or other card "
            "authentication/payment instrument data."
        ),
        "PHI": (
            "PHI: protected health information, such as medical record numbers, member "
            "IDs in healthcare context, diagnosis/treatment details, lab results, or "
            "health information linked to a person."
        ),
    }
    payload = {
        "table": table_input,
        "columns_to_evaluate": column_inputs,
        "scan_categories": scan_types,
        "preview": {
            "columns": preview.get("columns", []),
            "column_types": preview.get("column_types", {}),
            "rows": preview_rows_for_prompt(preview),
            "error": preview.get("error"),
        },
    }
    payload_json = json.dumps(payload, indent=2)
    selected_instructions = "\n".join(
        f"- {scan_scope_instructions[scan_type]}" for scan_type in scan_types
    )
    return (
        "You are a general data compliance expert.\n"
        "You are not performing a PII detection audit in Secoda.\n\n"
        "Review one table at a time using the table location, column metadata, and preview rows. "
        "Evaluate only the columns listed in `columns_to_evaluate` and only for the categories in `scan_categories`.\n\n"
        "Category definitions:\n"
        f"{selected_instructions}\n\n"
        "Return ONLY valid JSON (no markdown) with this exact shape:\n"
        "{\n"
        '  "decisions": [\n'
        "    {\n"
        '      "column_id": "string",\n'
        '      "is_sensitive": true,\n'
        '      "matched_categories": ["PII"],\n'
        '      "confidence": "high|medium|low",\n'
        '      "reason": "string",\n'
        '      "sample_evidence": "string"\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Table preview and columns to evaluate:\n"
        f"{payload_json}\n"
    )


def normalize_column_decisions(
    raw_decisions: Any,
    batch_inputs: list[dict[str, Any]],
    source_id: str,
    scan_types: list[str],
) -> dict[str, dict[str, str]]:
    expected_ids = {str(item["column_id"]) for item in batch_inputs}
    decisions: dict[str, dict[str, str]] = {}
    selected_types = set(scan_types)
    if not isinstance(raw_decisions, list):
        raw_decisions = []

    for decision in raw_decisions:
        if not isinstance(decision, dict):
            continue
        column_id = str(decision.get("column_id", "")).strip()
        if column_id not in expected_ids or column_id in decisions:
            continue
        matched_categories_raw = decision.get("matched_categories", [])
        if isinstance(matched_categories_raw, list):
            parsed_categories = [
                str(item).strip().upper()
                for item in matched_categories_raw
                if str(item).strip()
            ]
        elif isinstance(matched_categories_raw, str):
            parsed_categories = parse_scan_types_loose(matched_categories_raw)
        else:
            parsed_categories = []
        matched_categories = sorted(
            {category for category in parsed_categories if category in selected_types}
        )
        is_sensitive = to_bool(decision.get("is_sensitive")) or bool(matched_categories)
        if to_bool(decision.get("is_pii")) and "PII" in selected_types:
            is_sensitive = True
            if "PII" not in matched_categories:
                matched_categories.append("PII")
                matched_categories = sorted(set(matched_categories))
        decisions[column_id] = {
            "is_pii": csv_bool(is_sensitive),
            "review_pii": csv_bool(is_sensitive),
            "confidence": str(decision.get("confidence", "unknown")).strip().lower()
            or "unknown",
            "reason": str(decision.get("reason", "")).strip(),
            "sample_evidence": truncate_text(
                decision.get("sample_evidence", ""), max_length=1000
            ),
            "matched_categories": ",".join(matched_categories),
            "source_prompt_id": source_id,
        }

    for item in batch_inputs:
        column_id = str(item["column_id"])
        if column_id not in decisions:
            decisions[column_id] = {
                "is_pii": "FALSE",
                "review_pii": "FALSE",
                "confidence": "unknown",
                "reason": "AI response did not include this column.",
                "sample_evidence": "",
                "matched_categories": "",
                "source_prompt_id": source_id,
            }

    return decisions


def scan_table_with_ai(
    client: GeminiClient,
    *,
    table_input: dict[str, Any],
    column_inputs: list[dict[str, Any]],
    preview: dict[str, Any],
    scan_types: list[str],
) -> dict[str, dict[str, str]]:
    if not column_inputs:
        return {}

    print(
        f"    Calling Gemini for {len(column_inputs)} unmarked column(s) with {client.model}...",
        end=" ",
        flush=True,
    )
    parsed = client.generate_json(
        build_table_ai_prompt(
            table_input=table_input,
            column_inputs=column_inputs,
            preview=preview,
            scan_types=scan_types,
        )
    )
    print("done.")

    source_id = f"gemini:{client.model}"
    decisions = normalize_column_decisions(
        parsed.get("decisions"),
        column_inputs,
        source_id,
        scan_types,
    )
    flagged_count = sum(
        1 for decision in decisions.values() if decision["is_pii"] == "TRUE"
    )
    print(
        f"    Flagged {flagged_count} likely matching column(s) for this table "
        f"({', '.join(scan_types)})."
    )
    time.sleep(0.35)
    return decisions


def build_review_rows(
    secoda_client: SecodaClient,
    gemini_client: GeminiClient,
    inventory: list[TableInventory],
    scan_types: list[str],
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    print("\nFetching table previews and scanning one table at a time...")
    for table_index, item in enumerate(inventory, start=1):
        print(
            f"  [{table_index}/{len(inventory)}] "
            f"{item.database.title}.{item.schema.title}.{item.table.title}",
            flush=True,
        )
        preview: dict[str, Any] = {}
        preview_error = ""
        try:
            preview = secoda_client.get_table_preview(item.table.id)
            preview_error = str(preview.get("error") or "")
        except SecodaApiError as exc:
            preview_error = str(exc)

        table_rows: list[dict[str, str]] = []
        column_inputs: list[dict[str, Any]] = []
        for column in item.columns:
            samples = preview_column_samples(preview, column.title)
            sample_text = " | ".join(samples)
            row = {
                "secoda_column_id": column.id,
                "secoda_table_id": item.table.id,
                "database": item.database.title,
                "schema": item.schema.title,
                "table": item.table.title,
                "column": column.title,
                "data_type": column_data_type(column),
                "already_pii": csv_bool(column.pii),
                "is_pii": csv_bool(column.pii),
                "review_pii": csv_bool(column.pii),
                "confidence": "already_marked" if column.pii else "",
                "reason": "Column is already marked as PII in Secoda."
                if column.pii
                else "",
                "sample_evidence": sample_text,
                "matched_categories": "PII" if column.pii else "",
                "preview_error": preview_error,
                "source_prompt_id": "",
                "existing_tag_ids": json.dumps(parse_tag_ids(column.raw.get("tags"))),
                "secoda_url": resource_string(column.raw, "url"),
            }
            table_rows.append(row)

            if not column.pii:
                column_inputs.append(
                    {
                        "column_id": column.id,
                        "column": column.title,
                        "data_type": row["data_type"],
                        "sample_values": samples,
                        "preview_error": preview_error,
                    }
                )

        if column_inputs and not preview_error:
            table_input = {
                "database": item.database.title,
                "schema": item.schema.title,
                "table": item.table.title,
                "table_id": item.table.id,
            }
            decisions = scan_table_with_ai(
                gemini_client,
                table_input=table_input,
                column_inputs=column_inputs,
                preview=preview,
                scan_types=scan_types,
            )
            for row in table_rows:
                decision = decisions.get(row["secoda_column_id"])
                if decision:
                    row.update(decision)
        elif column_inputs:
            print(
                f"    Skipping Gemini for this table because preview failed: {preview_error}",
                flush=True,
            )

        rows.extend(table_rows)

    return rows


def write_review_reports(rows: list[dict[str, str]]) -> tuple[Path, Path]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = Path(f"{REPORT_PREFIX}_{timestamp}.json")
    csv_path = Path(f"{REPORT_PREFIX}_{timestamp}.csv")

    output = {
        "generated_at": now_utc_iso(),
        "columns": rows,
    }
    json_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    fieldnames = [
        "secoda_column_id",
        "secoda_table_id",
        "database",
        "schema",
        "table",
        "column",
        "data_type",
        "already_pii",
        "is_pii",
        "review_pii",
        "confidence",
        "reason",
        "sample_evidence",
        "matched_categories",
        "preview_error",
        "source_prompt_id",
        "existing_tag_ids",
        "secoda_url",
    ]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    return json_path, csv_path


def reviewed_pii_updates(
    csv_path: Path, update_tag_id: str | None = None
) -> tuple[list[dict[str, Any]], bool]:
    updates: list[dict[str, Any]] = []
    requested_tag_id = (update_tag_id or "").strip()
    with csv_path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fieldnames = set(reader.fieldnames or [])
        has_existing_tags_column = "existing_tag_ids" in fieldnames or "existing_tags" in fieldnames
        for row in reader:
            column_id = str(row.get("secoda_column_id", "")).strip()
            if (
                column_id
                and to_bool(row.get("review_pii"))
                and not to_bool(row.get("already_pii"))
            ):
                payload_data: dict[str, Any] = {"pii": True}
                if requested_tag_id and has_existing_tags_column:
                    existing_tags_value = row.get("existing_tag_ids")
                    if existing_tags_value in (None, ""):
                        existing_tags_value = row.get("existing_tags")
                    payload_data["tags"] = append_tag_id(
                        parse_tag_ids(existing_tags_value),
                        requested_tag_id,
                    )
                updates.append({"id": column_id, "data": payload_data})

    deduped: dict[str, dict[str, Any]] = {}
    for update in updates:
        deduped[str(update["id"])] = update
    return [deduped[key] for key in sorted(deduped)], has_existing_tags_column


def update_reviewed_pii_columns(
    client: SecodaClient,
    csv_path: Path,
    *,
    update_tag_id: str | None = None,
    update_tag_name: str | None = None,
) -> int:
    updates, has_existing_tags_column = reviewed_pii_updates(csv_path, update_tag_id)
    if not updates:
        print("No newly reviewed PII columns found in the CSV.")
        return 0

    print(f"\nUpdating {len(updates)} column(s) as PII in Secoda...")
    if update_tag_id:
        if not has_existing_tags_column:
            print(
                "CSV does not include existing tag snapshots; fetching current tags from Secoda."
            )
        tag_enriched_count = 0
        for update in updates:
            resource_id = str(update.get("id", "")).strip()
            if not resource_id:
                continue
            try:
                current_resource = client.get_resource(resource_id)
            except SecodaApiError as exc:
                print(
                    f"  Warning: could not fetch current tags for resource {resource_id}: {exc}"
                )
                continue
            update["data"]["tags"] = append_tag_id(
                parse_tag_ids(current_resource.get("tags")),
                update_tag_id,
            )
            tag_enriched_count += 1

        tagged_update_count = sum(
            1
            for update in updates
            if "tags" in update["data"]
        )
        print(
            f"Appending tag to updated resources: {update_tag_name or update_tag_id} "
            f"({tagged_update_count}/{len(updates)} payloads include tag updates; "
            f"{tag_enriched_count} fetched from API)"
        )

    updated_count = 0
    for batch in [updates[i : i + 100] for i in range(0, len(updates), 100)]:
        client.bulk_update_resources(batch)
        updated_count += len(batch)
        print(f"  Updated {updated_count}/{len(updates)} column(s).")
        time.sleep(0.25)
    return updated_count


def write_reports(
    findings: list[dict[str, str]], skipped: list[dict[str, str]]
) -> tuple[Path, Path]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = Path(f"{REPORT_PREFIX}_{timestamp}.json")
    csv_path = Path(f"{REPORT_PREFIX}_{timestamp}.csv")

    output = {
        "generated_at": now_utc_iso(),
        "findings": findings,
        "skipped_tables": skipped,
    }
    json_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "database",
                "schema",
                "table",
                "column",
                "confidence",
                "reason",
                "sample_evidence",
                "source_prompt_id",
            ],
        )
        writer.writeheader()
        for row in findings:
            writer.writerow(row)

    return json_path, csv_path


def choose_tables_to_scan(
    grouped_specs: dict[str, TableScanSpec],
    *,
    full_scan: bool,
    state: dict[str, Any],
) -> list[TableScanSpec]:
    state_tables = state.setdefault("tables", {})
    candidates: list[TableScanSpec] = []

    for key, spec in sorted(grouped_specs.items()):
        if not spec.unmarked_columns:
            continue

        fp = table_fingerprint(spec)
        last = state_tables.get(key)
        changed = (not last) or (last.get("fingerprint") != fp)

        if full_scan or changed:
            candidates.append(spec)

    return candidates


def update_state_after_scan(
    state: dict[str, Any], scanned_specs: list[TableScanSpec]
) -> None:
    state_tables = state.setdefault("tables", {})
    ts = now_utc_iso()
    for spec in scanned_specs:
        state_tables[spec.table_key] = {
            "fingerprint": table_fingerprint(spec),
            "last_scanned_at": ts,
        }


def run_one_scan_cycle(
    client: SecodaClient,
    gemini_client: GeminiClient,
    *,
    database_filter: set[str],
    schema_filter: set[str],
    single_table: str | None,
    scan_types: list[str],
    update_tag_name: str | None,
    update_tag_id: str | None,
    skip_review: bool,
) -> int:
    print(
        "Applying filters "
        f"(database={filter_label(database_filter)}, schema={filter_label(schema_filter)})..."
    )
    if single_table is not None:
        label = single_table or "first matching table"
        print(f"Single-table test mode enabled ({label}).")
    print(f"Compliance categories selected: {', '.join(scan_types)}")

    inventory = discover_table_inventory(
        client,
        database_filter=database_filter,
        schema_filter=schema_filter,
        single_table=single_table,
    )
    if not inventory:
        print("No matching tables/columns found for the selected filters.")
        return 0

    column_count = sum(len(item.columns) for item in inventory)
    print(f"\nDiscovered {len(inventory)} table(s) and {column_count} column(s).")

    rows = build_review_rows(client, gemini_client, inventory, scan_types)

    json_path, csv_path = write_review_reports(rows)
    likely_sensitive_count = sum(1 for row in rows if to_bool(row.get("is_pii")))

    print("\nScan complete.")
    print(f"Likely matching columns ({', '.join(scan_types)}): {likely_sensitive_count}")
    print(f"JSON report: {json_path.resolve()}")
    print(f"CSV report:  {csv_path.resolve()}")
    if skip_review:
        print(
            "\nSkipping manual CSV review (--skip-review enabled). "
            "Applying updates using current review_pii values."
        )
        updated_count = update_reviewed_pii_columns(
            client,
            csv_path,
            update_tag_id=update_tag_id,
            update_tag_name=update_tag_name,
        )
        print(f"Updated {updated_count} newly marked PII column(s).")
    else:
        print("\nOpen the CSV in Excel, review the review_pii column, then save the CSV.")
        if prompt_yes_no(
            "Continue and update reviewed PII columns now?", default_yes=False
        ):
            input("Press Enter after you have saved the reviewed CSV...")
            updated_count = update_reviewed_pii_columns(
                client,
                csv_path,
                update_tag_id=update_tag_id,
                update_tag_name=update_tag_name,
            )
            print(f"Updated {updated_count} newly marked PII column(s).")

    return likely_sensitive_count


def print_response_summary(label: str, response: dict[str, Any]) -> None:
    results = response.get("results", [])
    if not isinstance(results, list):
        results = []
    print(f"\nDebug: {label}")
    print(
        f"  count={response.get('count')!r}, total_pages={response.get('total_pages')!r}"
    )
    print(f"  next={response.get('links', {}).get('next')!r}")
    print(f"  results_on_page={len(results)}")
    if response.get("count") and not results:
        print(
            "  Warning: API reported a non-zero count but returned no rows on this page."
        )


def print_column_samples(columns: list[dict[str, Any]], sample_size: int = 5) -> None:
    print(
        f"\nSample of raw fields from first {min(sample_size, len(columns))} column(s):"
    )
    for item in columns[:sample_size]:
        db, schema, table, column_name = derive_location(item)
        print(f"  title={item.get('title')!r}")
        print(f"  title_full={item.get('title_full')!r}")
        print(f"  table_database={item.get('table_database')!r}")
        print(f"  table_schema={item.get('table_schema')!r}")
        print(f"  table_title={item.get('table_title')!r}")
        print(f"  entity_type={item.get('entity_type')!r}")
        print(f"  derived=({db!r}, {schema!r}, {table!r}, {column_name!r})")
        print()


def debug_columns(
    client: SecodaClient, database_filter: set[str], schema_filter: set[str]
) -> None:
    print(f"\nDebug: API base URL is {client.base_url}")

    column_page, first_columns, column_response = client.fetch_columns_page(
        1, page_size=50
    )
    print_response_summary(f"/table/columns page {column_page}", column_response)

    _, _, catalog_response = client.fetch_catalog_page(
        1,
        entity_type="column",
        page_size=50,
    )
    print_response_summary(
        "/resource/catalog with entity_type filter", catalog_response
    )

    if not first_columns:
        print(
            "\nNo columns returned from /table/columns. Check whether this API key has Resources read access."
        )
        return

    print("\nFetching all columns from /table/columns for local filter diagnostics...")
    columns = client.list_columns()
    summarize_column_locations(
        columns,
        database_filter=database_filter,
        schema_filter=schema_filter,
        max_locations=100,
    )
    print_column_samples(columns)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan Secoda columns for possible PII/PCI/PHI."
    )
    parser.add_argument(
        "--scan-for",
        default=None,
        help=(
            "Compliance categories to scan (comma separated). "
            f"Supported values: {', '.join(SUPPORTED_SCAN_TYPES)}. "
            f"Default: {DEFAULT_SCAN_FOR}."
        ),
    )
    parser.add_argument(
        "--debug-columns",
        action="store_true",
        help="Show raw column fields and filter matching, then exit.",
    )
    parser.add_argument(
        "--review-csv",
        type=Path,
        help="Skip scanning and update Secoda from an already reviewed CSV.",
    )
    parser.add_argument(
        "--single-table",
        nargs="?",
        const="",
        default=None,
        help=(
            "Test mode: scan only one table. Provide a table name to scan that table, "
            "or omit the value to scan the first matching table."
        ),
    )
    parser.add_argument(
        "--update-tag",
        default=None,
        help=(
            "Optional tag to append to each newly updated resource, "
            'for example: "AI Generated". If omitted, you will be prompted during setup.'
        ),
    )
    parser.add_argument(
        "--skip-review",
        action="store_true",
        help=(
            "Skip manual CSV review and apply updates immediately. "
            "Default: false."
        ),
    )
    args, _ = parser.parse_known_args()

    print("Secoda PII Scanner")
    print("==================")
    print(
        "This tool scans catalog columns, asks Gemini to classify sampled values for selected compliance categories, and exports a reviewable CSV."
    )

    base_url = prompt_input("Secoda API base URL", default=DEFAULT_BASE_URL)
    api_key = HARDCODED_API_KEY.strip() or prompt_input(
        "Secoda API key or Authorization header",
        secret=True,
    )
    if HARDCODED_API_KEY.strip():
        print("Using HARDCODED_API_KEY from script.")

    client = SecodaClient(base_url=base_url, api_key=api_key)
    if args.update_tag is None:
        update_tag_name = canonical_name(
            prompt_optional_input(
                'Optional tag to append on updated resources (for example "AI Generated")'
            )
        )
    else:
        update_tag_name = canonical_name(args.update_tag)

    update_tag_id = ""
    if update_tag_name:
        try:
            update_tag_id, created_tag = resolve_or_create_tag_id(client, update_tag_name)
        except SecodaApiError as exc:
            print(f"\nError resolving update tag '{update_tag_name}': {exc}")
            return 1
        if created_tag:
            print(f"Created tag '{update_tag_name}' ({update_tag_id})")
        else:
            print(f"Using existing tag '{update_tag_name}' ({update_tag_id})")

    if args.review_csv:
        try:
            updated_count = update_reviewed_pii_columns(
                client,
                args.review_csv,
                update_tag_id=update_tag_id or None,
                update_tag_name=update_tag_name or None,
            )
            print(f"Updated {updated_count} newly marked PII column(s).")
            return 0
        except SecodaApiError as exc:
            print(f"\nError: {exc}")
            return 1

    if HARDCODED_DATABASES.strip():
        database_filter = csv_filter_values(HARDCODED_DATABASES)
        print(f"Using HARDCODED_DATABASES from script: {filter_label(database_filter)}")
    else:
        database_filter = prompt_optional_csv("Database(s) to scan")

    if HARDCODED_SCHEMAS.strip():
        schema_filter = csv_filter_values(HARDCODED_SCHEMAS)
        print(f"Using HARDCODED_SCHEMAS from script: {filter_label(schema_filter)}")
    else:
        schema_filter = prompt_optional_csv("Schema(s) to scan")

    if args.scan_for is None:
        try:
            scan_types = prompt_scan_types(default_value=DEFAULT_SCAN_FOR)
        except ValueError as exc:
            print(f"\nError: {exc}")
            return 1
    else:
        try:
            scan_types = parse_scan_types(args.scan_for)
        except ValueError as exc:
            print(f"\nError: {exc}")
            return 1

    single_table = args.single_table
    if HARDCODED_SINGLE_TABLE.strip():
        single_table = HARDCODED_SINGLE_TABLE.strip()
        print(f"Using HARDCODED_SINGLE_TABLE from script: {single_table}")

    if args.debug_columns:
        client = SecodaClient(base_url=base_url, api_key=api_key)
        debug_columns(client, database_filter, schema_filter)
        return 0

    gemini_api_key = HARDCODED_GEMINI_API_KEY.strip() or prompt_input(
        "Gemini API key",
        secret=True,
    )
    if HARDCODED_GEMINI_API_KEY.strip():
        print("Using HARDCODED_GEMINI_API_KEY from script.")

    gemini_model = HARDCODED_GEMINI_MODEL.strip() or prompt_input(
        "Gemini model",
        default=DEFAULT_GEMINI_MODEL,
    )
    gemini_client = GeminiClient(gemini_api_key, model=gemini_model)

    try:
        run_one_scan_cycle(
            client,
            gemini_client,
            database_filter=database_filter,
            schema_filter=schema_filter,
            single_table=single_table,
            scan_types=scan_types,
            update_tag_name=update_tag_name or None,
            update_tag_id=update_tag_id or None,
            skip_review=args.skip_review,
        )
        return 0
    except KeyboardInterrupt:
        print("\nStopped by user.")
        return 0
    except SecodaApiError as exc:
        print(f"\nError: {exc}")
        return 1
    except GeminiApiError as exc:
        print(f"\nGemini error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
