import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import secoda_data_scanner as scanner


class TestParsingHelpers(unittest.TestCase):
    def test_parse_scan_types_valid(self):
        self.assertEqual(scanner.parse_scan_types("pii,phi"), ["PHI", "PII"])

    def test_parse_scan_types_invalid_value_raises(self):
        with self.assertRaises(ValueError):
            scanner.parse_scan_types("pii,not_real")

    def test_parse_tag_ids_from_json_string(self):
        value = '["04654d61-4f64-4f08-b697-3915b5137c49", "bad-id"]'
        self.assertEqual(
            scanner.parse_tag_ids(value),
            ["04654d61-4f64-4f08-b697-3915b5137c49"],
        )

    def test_parse_tag_ids_from_list_dicts_and_dedupes(self):
        value = [
            {"id": "04654d61-4f64-4f08-b697-3915b5137c49"},
            {"id": "04654d61-4f64-4f08-b697-3915b5137c49"},
            {"id": "429693a2-a5e7-4525-b413-ece5e96bc5b3"},
        ]
        self.assertEqual(
            scanner.parse_tag_ids(value),
            [
                "04654d61-4f64-4f08-b697-3915b5137c49",
                "429693a2-a5e7-4525-b413-ece5e96bc5b3",
            ],
        )

    def test_append_tag_id_appends_when_missing(self):
        self.assertEqual(
            scanner.append_tag_id(
                ["04654d61-4f64-4f08-b697-3915b5137c49"],
                "429693a2-a5e7-4525-b413-ece5e96bc5b3",
            ),
            [
                "04654d61-4f64-4f08-b697-3915b5137c49",
                "429693a2-a5e7-4525-b413-ece5e96bc5b3",
            ],
        )

    def test_append_tag_id_no_duplicate(self):
        self.assertEqual(
            scanner.append_tag_id(
                ["04654d61-4f64-4f08-b697-3915b5137c49"],
                "04654d61-4f64-4f08-b697-3915b5137c49",
            ),
            ["04654d61-4f64-4f08-b697-3915b5137c49"],
        )


class TestTagResolution(unittest.TestCase):
    def test_resolve_or_create_tag_id_uses_existing(self):
        client = MagicMock()
        client.list_tags.return_value = [
            {"id": "04654d61-4f64-4f08-b697-3915b5137c49", "name": "AI Generated"}
        ]

        tag_id, created = scanner.resolve_or_create_tag_id(client, "AI Generated")

        self.assertEqual(tag_id, "04654d61-4f64-4f08-b697-3915b5137c49")
        self.assertFalse(created)
        client.create_tag.assert_not_called()

    def test_resolve_or_create_tag_id_creates_missing(self):
        client = MagicMock()
        client.list_tags.return_value = []
        client.create_tag.return_value = {
            "id": "429693a2-a5e7-4525-b413-ece5e96bc5b3",
            "name": "AI Generated",
        }

        tag_id, created = scanner.resolve_or_create_tag_id(client, "AI Generated")

        self.assertEqual(tag_id, "429693a2-a5e7-4525-b413-ece5e96bc5b3")
        self.assertTrue(created)
        client.create_tag.assert_called_once()


class TestSecodaClientPaths(unittest.TestCase):
    def test_get_resource_uses_resource_all_path(self):
        client = scanner.SecodaClient(base_url="https://app.secoda.co/api/v1", api_key="x")
        with patch.object(client, "_request", return_value={}) as req:
            client.get_resource("abc-123")
        req.assert_called_once()
        self.assertEqual(req.call_args.args[0], "GET")
        self.assertEqual(req.call_args.args[1], "/resource/all/abc-123")


class TestCsvUpdateFlow(unittest.TestCase):
    def _write_csv(self, rows, headers):
        temp_dir = tempfile.TemporaryDirectory()
        csv_path = Path(temp_dir.name) / "report.csv"
        with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        return temp_dir, csv_path

    def test_reviewed_pii_updates_with_tag_ids_column(self):
        rows = [
            {
                "secoda_column_id": "0c7f5007-fc3f-4ea2-84fd-1a81aa6acae1",
                "review_pii": "TRUE",
                "already_pii": "FALSE",
                "existing_tag_ids": '["04654d61-4f64-4f08-b697-3915b5137c49"]',
            }
        ]
        temp_dir, csv_path = self._write_csv(rows, list(rows[0].keys()))
        try:
            updates, has_column = scanner.reviewed_pii_updates(
                csv_path, update_tag_id="429693a2-a5e7-4525-b413-ece5e96bc5b3"
            )
        finally:
            temp_dir.cleanup()

        self.assertTrue(has_column)
        self.assertEqual(len(updates), 1)
        self.assertEqual(
            updates[0]["data"]["tags"],
            [
                "04654d61-4f64-4f08-b697-3915b5137c49",
                "429693a2-a5e7-4525-b413-ece5e96bc5b3",
            ],
        )

    def test_update_reviewed_pii_columns_fetches_current_tags_and_updates(self):
        rows = [
            {
                "secoda_column_id": "0c7f5007-fc3f-4ea2-84fd-1a81aa6acae1",
                "review_pii": "TRUE",
                "already_pii": "FALSE",
                "existing_tag_ids": "[]",
            },
            {
                "secoda_column_id": "a6268727-2c3a-45ce-a12f-9e34ad00ad3b",
                "review_pii": "TRUE",
                "already_pii": "FALSE",
                "existing_tag_ids": "[]",
            },
        ]
        temp_dir, csv_path = self._write_csv(rows, list(rows[0].keys()))
        client = MagicMock()
        client.get_resource.side_effect = [
            {"tags": ["04654d61-4f64-4f08-b697-3915b5137c49"]},
            {"tags": []},
        ]
        client.bulk_update_resources.return_value = []
        try:
            updated = scanner.update_reviewed_pii_columns(
                client,
                csv_path,
                update_tag_id="429693a2-a5e7-4525-b413-ece5e96bc5b3",
                update_tag_name="AI Generated",
            )
        finally:
            temp_dir.cleanup()

        self.assertEqual(updated, 2)
        self.assertEqual(client.get_resource.call_count, 2)
        self.assertEqual(client.bulk_update_resources.call_count, 1)
        payload = client.bulk_update_resources.call_args.args[0]
        self.assertEqual(payload[0]["data"]["tags"], [
            "04654d61-4f64-4f08-b697-3915b5137c49",
            "429693a2-a5e7-4525-b413-ece5e96bc5b3",
        ])
        self.assertEqual(payload[1]["data"]["tags"], [
            "429693a2-a5e7-4525-b413-ece5e96bc5b3"
        ])


class TestRunOneScanCycleReviewBehavior(unittest.TestCase):
    def test_skip_review_updates_immediately(self):
        client = MagicMock()
        gemini = MagicMock()
        fake_inventory = [MagicMock(columns=[1])]
        fake_rows = [{"is_pii": "TRUE"}]
        fake_json = Path("/tmp/report.json")
        fake_csv = Path("/tmp/report.csv")

        with patch.object(scanner, "discover_table_inventory", return_value=fake_inventory), patch.object(
            scanner, "build_review_rows", return_value=fake_rows
        ), patch.object(
            scanner, "write_review_reports", return_value=(fake_json, fake_csv)
        ), patch.object(
            scanner, "update_reviewed_pii_columns", return_value=1
        ) as update_mock, patch.object(
            scanner, "prompt_yes_no"
        ) as prompt_mock:
            result = scanner.run_one_scan_cycle(
                client,
                gemini,
                database_filter=set(),
                schema_filter=set(),
                single_table=None,
                scan_types=["PII"],
                update_tag_name="AI Generated",
                update_tag_id="429693a2-a5e7-4525-b413-ece5e96bc5b3",
                skip_review=True,
            )

        self.assertEqual(result, 1)
        update_mock.assert_called_once()
        prompt_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
