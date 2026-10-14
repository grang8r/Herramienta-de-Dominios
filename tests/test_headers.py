import unittest
from src.security_headers import analyze_headers

class TestHeaders(unittest.TestCase):
    def test_invalid_url(self):
        self.assertIn("error", analyze_headers("example.com"))

if __name__ == "__main__":
    unittest.main()
