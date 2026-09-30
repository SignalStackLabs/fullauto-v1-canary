import unittest

from fullauto_canary import greet


class TestGreet(unittest.TestCase):
    def test_greet(self):
        self.assertEqual(greet("factory"), "Hello, factory!")


if __name__ == "__main__":
    unittest.main()
