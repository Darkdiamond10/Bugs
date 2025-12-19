import unittest
from dark_dragon.apk import ApkAnalyzer

class TestApkAnalyzer(unittest.TestCase):
    def test_extract_domains_urls(self):
        sample_text = [
            'Check out https://example.com/api/v1 for more info.',
            'Contact support@test-domain.io or visit http://sub.test.co.uk',
            'Some random text with a hidden domain like secret-api.aws.amazon.com inside.'
        ]
        urls, domains = ApkAnalyzer.extract_domains_urls(sample_text)

        self.assertIn('https://example.com/api/v1', urls)
        self.assertIn('http://sub.test.co.uk', urls)

        self.assertIn('example.com', domains)
        self.assertIn('test-domain.io', domains)
        self.assertIn('sub.test.co.uk', domains)
        self.assertIn('secret-api.aws.amazon.com', domains)

    def test_check_cdn(self):
        self.assertTrue(ApkAnalyzer.check_cdn('cdn.cloudflare.net'))
        self.assertTrue(ApkAnalyzer.check_cdn('my-bucket.s3.amazonaws.com'))
        self.assertFalse(ApkAnalyzer.check_cdn('mysite.com'))

if __name__ == '__main__':
    unittest.main()
