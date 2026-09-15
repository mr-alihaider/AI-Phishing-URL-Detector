"""
Unit tests for Flask Web API endpoints.
"""

import unittest
import sys
import os
import json

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.web.app import app


class TestWebApi(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_health_check(self):
        """GET /api/health should return 200 with status healthy."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["model_loaded"])

    def test_predict_single_endpoint(self):
        """POST /api/predict should analyze the provided URL."""
        payload = {"url": "https://www.google.com"}
        response = self.client.post(
            "/api/predict",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertIn("data", data)
        self.assertEqual(data["data"]["label"], "Legitimate")

    def test_predict_batch_endpoint(self):
        """POST /api/batch should process list of URLs."""
        payload = {
            "urls": [
                "https://wikipedia.org",
                "http://secure-login-chase-update.top/auth"
            ]
        }
        response = self.client.post(
            "/api/batch",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["summary"]["total_scanned"], 2)


if __name__ == "__main__":
    unittest.main()
