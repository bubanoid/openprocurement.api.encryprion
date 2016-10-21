import nacl.secret
import nacl.utils
from StringIO import StringIO
from .response import FileObjResponse


def generate_secret_key():
    return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE).encode('hex')


def encrypt_file(key, fileobj, nonce=None):
    if nonce is None:
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    box = nacl.secret.SecretBox(key)
    encrypted = box.encrypt(fileobj.read(), nonce)
    return FileObjResponse(StringIO(encrypted))


def decrypt_file(key, fileobj):
    box = nacl.secret.SecretBox(key)
    decrypted = box.decrypt(fileobj.read())
    return FileObjResponse(StringIO(decrypted))
