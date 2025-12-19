import unittest
from dark_dragon.utils import ScannerUtils

class TestUtils(unittest.TestCase):
    def test_file_exists(self):
        # We know main.py exists
        self.assertTrue(ScannerUtils.check_file_exists('main.py'))
        self.assertFalse(ScannerUtils.check_file_exists('non_existent_file.xyz'))

if __name__ == '__main__':
    unittest.main()
