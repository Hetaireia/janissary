import sys
import unittest
sys.path.insert(0, "benchmark/track_c")
from score import _placeholder_path_match


class TestPlaceholderPathMatch(unittest.TestCase):
    def test_single_segment_match(self):
        self.assertTrue(_placeholder_path_match("/users/v1/name1", "/users/v1/{username}"))

    def test_single_segment_missing(self):
        self.assertFalse(_placeholder_path_match("/users/v1", "/users/v1/{username}"))

    def test_single_segment_extra(self):
        self.assertFalse(_placeholder_path_match("/users/v1/name1/email", "/users/v1/{username}"))

    def test_multi_segment_match(self):
        self.assertTrue(_placeholder_path_match("/api/v1/owner/repo", "/api/v1/{owner}/{repo}"))

    def test_multi_segment_missing(self):
        self.assertFalse(_placeholder_path_match("/api/v1/owner", "/api/v1/{owner}/{repo}"))

    def test_multi_segment_extra(self):
        self.assertFalse(_placeholder_path_match("/api/v1/owner/repo/issues", "/api/v1/{owner}/{repo}"))


if __name__ == "__main__":
    unittest.main()