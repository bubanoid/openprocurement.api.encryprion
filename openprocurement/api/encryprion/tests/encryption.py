# -*- coding: utf-8 -*-
import unittest
import webtest
import os
import collections


class EncryptionTest(unittest.TestCase):

    def setUp(self):
        self.app = webtest.TestApp("config:tests.ini", relative_to=os.path.dirname(__file__))
        self.app.authorization = ('Basic', ('token', ''))

    def test_key(self):
        response = self.app.get('/')
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(1, len(response.json))
        self.assertIn('key', response.json)

    def test_flow(self):
        key = self.app.get('/').json['key']
        response = self.app.post('/encrypt_file', collections.OrderedDict([('key', key), ('file', webtest.forms.Upload('filename.txt', 'Very important information'))]))
        encrypted_file = response.body
        self.assertEqual(response.status, '200 OK')
        self.assertNotEqual(encrypted_file, 'Very important information')
        response = self.app.post('/decrypt_file', collections.OrderedDict([('key', key), ('file', webtest.forms.Upload('filename.txt', encrypted_file))]))
        decrypted_file = response.body
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(decrypted_file, 'Very important information')

        # Encrypt without file
        response = self.app.post('/encrypt_file', collections.OrderedDict([('key', key)]), status=400)
        self.assertEqual(response.status, '400 Bad Request')
        self.assertEqual(response.body, '400 Bad Request\n\nThe server could not comply with the request since it is either malformed or otherwise incorrect.\n\n\nMissed file.\n\n')
        # Decrypt decrypted_file
        response = self.app.post('/decrypt_file', collections.OrderedDict([('key', key), ('file', webtest.forms.Upload('filename.txt', decrypted_file))]), status=400)
        self.assertEqual(response.status, '400 Bad Request')
        self.assertEqual(response.body, '400 Bad Request\n\nThe server could not comply with the request since it is either malformed or otherwise incorrect.\n\n\nDecryption failed. Ciphertext failed verification\n\n')
        # Decrypt without file
        response = self.app.post('/decrypt_file', collections.OrderedDict([('key', key)]), status=400)
        self.assertEqual(response.status, '400 Bad Request')
        self.assertEqual(response.body, '400 Bad Request\n\nThe server could not comply with the request since it is either malformed or otherwise incorrect.\n\n\nMissed encrypted file.\n\n')
        # Encrypt with empty key
        response = self.app.post('/encrypt_file', collections.OrderedDict([('key', ''), ('file', webtest.forms.Upload('filename.txt', 'Very important information'))]), status=400)
        self.assertIn(response.status, '400 Bad Request')
        self.assertEqual(response.body, '400 Bad Request\n\nThe server could not comply with the request since it is either malformed or otherwise incorrect.\n\n\nThe key must be exactly 32 bytes long.\n\n')
        # Encrypt with Invalid key
        response = self.app.post('/encrypt_file', collections.OrderedDict([('key', 'a514cdc3c198421de6a746961d34f20147b7614c85a39297ffb07570b28hello'), ('file', webtest.forms.Upload('filename.txt', 'Very important information'))]), status=400)
        self.assertIn(response.status, '400 Bad Request')
        self.assertEqual(response.body, '400 Bad Request\n\nThe server could not comply with the request since it is either malformed or otherwise incorrect.\n\n\nInvalid key: Non-hexadecimal digit found.\n\n')
        # Encrypt without key
        response = self.app.post('/encrypt_file', collections.OrderedDict([('file', webtest.forms.Upload('filename.txt', 'Very important information'))]), status=400)
        self.assertIn(response.status, '400 Bad Request')
        self.assertEqual(response.body, '400 Bad Request\n\nThe server could not comply with the request since it is either malformed or otherwise incorrect.\n\n\nKey missed.\n\n')
        # Decrypt with empty key
        response = self.app.post('/decrypt_file', collections.OrderedDict([('key', ''), ('file', webtest.forms.Upload('filename.txt', encrypted_file))]), status=400)
        self.assertIn(response.status, '400 Bad Request')
        self.assertEqual(response.body, '400 Bad Request\n\nThe server could not comply with the request since it is either malformed or otherwise incorrect.\n\n\nThe key must be exactly 32 bytes long.\n\n')
        # Decrypt with invalid key
        response = self.app.post('/decrypt_file', collections.OrderedDict([('key', 'a514cdc3c198421de6a746961d34f20147b7614c85a39297ffb07570b28hello'), ('file', webtest.forms.Upload('filename.txt', encrypted_file))]), status=400)
        self.assertIn(response.status, '400 Bad Request')
        self.assertEqual(response.body, '400 Bad Request\n\nThe server could not comply with the request since it is either malformed or otherwise incorrect.\n\n\nInvalid key: Non-hexadecimal digit found.\n\n')
        # Decrypt without key
        response = self.app.post('/decrypt_file', collections.OrderedDict([('file', webtest.forms.Upload('filename.txt', encrypted_file))]), status=400)
        self.assertIn(response.status, '400 Bad Request')
        self.assertEqual(response.body, '400 Bad Request\n\nThe server could not comply with the request since it is either malformed or otherwise incorrect.\n\n\nKey missed.\n\n')
        # Decrypt with other key
        response = self.app.post('/decrypt_file', collections.OrderedDict([('key', 'a7bfc49610fcd219021c86749f3ee09e1324d9c4de13f0d5f8cb569dd319e4e4'), ('file', webtest.forms.Upload('filename.txt', encrypted_file))]), status=400)
        self.assertIn(response.status, '400 Bad Request')
        self.assertEqual(response.body, '400 Bad Request\n\nThe server could not comply with the request since it is either malformed or otherwise incorrect.\n\n\nDecryption failed. Ciphertext failed verification\n\n')


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(EncryptionTest))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
