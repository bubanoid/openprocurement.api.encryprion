from pyramid.view import view_config
import nacl.secret
import nacl.utils
from .response import FileObjResponse
from pyramid.response import FileIter
from StringIO import StringIO
from .utils import generate_secret_key
from .utils import encrypt_file
from .utils import decrypt_file
from .utils import validate_key
from pyramid.httpexceptions import HTTPBadRequest

@view_config(route_name='generate_key', renderer='json')
def generate_key_view(request):
    return {'key': generate_secret_key()}


@view_config(route_name='encrypt_file', decorator=(validate_key,))
def encrypt_file_view(request):
    key = request.POST.get('key').decode('hex')
    if not 'file' in request.POST:
        raise HTTPBadRequest('Missed file.')
    request.POST.get('file').file.seek(0)
    return encrypt_file(key, request.POST.get('file').file, nonce=request.POST.get('nonce'))


@view_config(route_name='decrypt_file', decorator=(validate_key,))
def decrypt_file_view(request):
    key = request.POST.get('key').decode('hex')
    if not 'file' in request.POST:
        raise HTTPBadRequest('Missed encrypted file.')
    request.POST.get('file').file.seek(0)
    return decrypt_file(key, request.POST.get('file').file)
