import json
import unittest

from mcp_server_core.response import ToolResultListDict


class TestResponseModule(unittest.TestCase):
    def test_basic_structure(self):
        items = [{"id": 1, "name": "alpha"}, {"id": 2, "name": "beta"}]
        res = ToolResultListDict(items)

        self.assertIsInstance(res, dict)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["total"], 2)
        self.assertEqual(res["count"], 2)
        self.assertEqual(res["items"], items)
        self.assertEqual(res["entries"], items)

    def test_custom_key_and_extra_kwargs(self):
        items = ["apple", "banana", "orange"]
        res = ToolResultListDict(
            items,
            key="fruits",
            status="partial",
            page=1,
            has_more=False,
        )

        self.assertEqual(res["status"], "partial")
        self.assertEqual(res["fruits"], items)
        self.assertEqual(res["entries"], items)
        self.assertEqual(res["page"], 1)
        self.assertFalse(res["has_more"])

    def test_list_indexing_and_slicing(self):
        items = ["a", "b", "c", "d", "e"]
        res = ToolResultListDict(items)

        # Indexing
        self.assertEqual(res[0], "a")
        self.assertEqual(res[2], "c")
        self.assertEqual(res[-1], "e")
        with self.assertRaises(IndexError):
            _ = res[10]

        # Slicing
        self.assertEqual(res[1:4], ["b", "c", "d"])
        self.assertEqual(res[:2], ["a", "b"])
        self.assertEqual(res[::-1], ["e", "d", "c", "b", "a"])

    def test_list_iteration_and_len(self):
        items = [10, 20, 30]
        res = ToolResultListDict(items)

        self.assertEqual(len(res), 3)
        collected = []
        for x in res:
            collected.append(x)
        self.assertEqual(collected, [10, 20, 30])

    def test_membership(self):
        items = [{"id": 101}, {"id": 102}]
        res = ToolResultListDict(items, key="records")

        # Dict keys check
        self.assertIn("status", res)
        self.assertIn("records", res)
        self.assertIn("total", res)

        # List items check
        self.assertIn({"id": 101}, res)
        self.assertNotIn({"id": 999}, res)

    def test_json_serialization(self):
        items = [{"task": "deploy", "done": True}]
        res = ToolResultListDict(items, key="tasks", environment="prod")

        serialized = json.dumps(res)
        deserialized = json.loads(serialized)

        self.assertEqual(deserialized["status"], "success")
        self.assertEqual(deserialized["total"], 1)
        self.assertEqual(deserialized["tasks"], items)
        self.assertEqual(deserialized["entries"], items)
        self.assertEqual(deserialized["environment"], "prod")


if __name__ == "__main__":
    unittest.main()
