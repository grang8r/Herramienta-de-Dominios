import unittest
from src.ua_analyzer import classify_user_agent

class TestUserAgent(unittest.TestCase):
    def test_curl(self):
        self.assertIn("curl", classify_user_agent("curl/8.5.0").lower())
    def test_python_requests(self):
        self.assertIn("Python Requests", classify_user_agent("python-requests/2.32.0"))
    def test_empty(self):
        self.assertEqual(classify_user_agent(""), "Vacío")

if __name__ == "__main__":
    unittest.main()
