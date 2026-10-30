import unittest
from unittest.mock import MagicMock

from janissary.engine.scanner import Scanner


class TestPathDispatch(unittest.TestCase):
    def _make(self, method):
        sess = MagicMock()
        sess.headers = {}
        sess.cookies = {}
        sess.get.return_value = MagicMock(status_code=200, text="ok")
        sess.post.return_value = MagicMock(status_code=200, text="ok")
        s = Scanner(
            target="http://example.test/users/v1/{username}",
            params=["username"],
            method=method,
            inject_in="path",
            baseline_value="name1",
            session=sess,
            detect_waf=False,
        )
        return s, sess

    def test_get_uses_session_get(self):
        s, sess = self._make("GET")
        s._request(s.target, "username", "alice")
        sess.get.assert_called_once()
        sess.post.assert_not_called()
        self.assertIn("/users/v1/alice", sess.get.call_args[0][0])

    def test_post_uses_session_post(self):
        s, sess = self._make("POST")
        s._request(s.target, "username", "alice")
        sess.post.assert_called_once()
        sess.get.assert_not_called()
        self.assertIn("/users/v1/alice", sess.post.call_args[0][0])

    def test_payload_url_quoted(self):
        s, sess = self._make("GET")
        s._request(s.target, "username", "a b'c")
        self.assertIn("/users/v1/a%20b%27c", sess.get.call_args[0][0])

    def test_kwargs_preserved(self):
        s, sess = self._make("GET")
        s._request(s.target, "username", "x")
        kw = sess.get.call_args[1]
        for k in ("headers", "timeout", "allow_redirects", "proxies"):
            self.assertIn(k, kw)


if __name__ == "__main__":
    unittest.main()