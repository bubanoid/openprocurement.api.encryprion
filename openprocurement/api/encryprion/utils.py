import libnacl.secret
import libnacl.utils
from libnacl import CryptError
from StringIO import StringIO
from .response import FileObjResponse
from pyramid.httpexceptions import HTTPBadRequest


def generate_secret_key():
    return libnacl.utils.salsa_key().encode('hex')


def encrypt_file(key, fileobj, nonce=None):
    if nonce is None:
        nonce = libnacl.utils.rand_nonce()
    box = libnacl.secret.SecretBox(key)
    encrypted = box.encrypt(fileobj.read(), nonce)
    return FileObjResponse(StringIO(encrypted))


def decrypt_file(key, fileobj):
    box = libnacl.secret.SecretBox(key)
    try:
        decrypted = box.decrypt(fileobj.read())
    except ValueError as e:
        raise HTTPBadRequest(e.message)
    return FileObjResponse(StringIO(decrypted))


def validate_key(view_callable):
    def inner(context, request):
        key = request.params.get('key')
        if key == None:
            raise HTTPBadRequest('Key missed.')
        if len(key) != 64:
            raise HTTPBadRequest('The key must be exactly 32 bytes long.')
        try:
            key.decode('hex')
        except TypeError:
            raise HTTPBadRequest('Invalid key: Non-hexadecimal digit found.')
        return view_callable(context, request)
    return inner
