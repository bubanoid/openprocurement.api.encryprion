import nacl.secret
import nacl.utils
from nacl.exceptions import CryptoError
from StringIO import StringIO
from .response import FileObjResponse
import json
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.view import view_config

error = {
    'message': {
        'status': 'error',
        'errors': [{
            'description': '',
            'location': 'body',
            'name': 'key'
        }]
    },
    'code': 422
}

class ValidationFailure(Exception):
    def __init__(self, msg):
        self.msg = msg

@view_config(context=ValidationFailure, renderer='json')
def failed_validation(exc, request):
    response = HTTPBadRequest()
    response.body = json.dumps(exc.msg['message'])
    response.status_int = exc.msg['code']
    response.content_type = 'application/json'
    return response

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
    try:
        decrypted = box.decrypt(fileobj.read())
    except CryptoError as e:
        error['message']['errors'][0]['description'] = e.message
        error['code'] = 500
        raise ValidationFailure(error)
    return FileObjResponse(StringIO(decrypted))


def validate_key(view_callable):
    def inner(context, request):
        key = request.params.get('key')
        if key == None:
            error['message']['errors'][0]['description'] = 'Key missed.'
            error['code'] = 422
            raise ValidationFailure(error)
        if len(key) != 64:
            error['message']['errors'][0]['description'] = 'The key must be exactly 32 bytes long.'
            error['code'] = 422
            raise ValidationFailure(error)
        if len(key) != 64:
            error['code'] = 422
            error['message']['errors'][0]['description'] = 'The key must be exactly 32 bytes long.'
            raise ValidationFailure(error)
        try:
            key.decode('hex')
        except TypeError:
            error['code'] = 422
            error['message']['errors'][0]['description'] = 'Invalid key: Non-hexadecimal digit found.'
            raise ValidationFailure(error)
        return view_callable(context, request)
    return inner
