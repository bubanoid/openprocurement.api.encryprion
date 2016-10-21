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



def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(EncryptionTest))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
