from pyramid.config import Configurator
import datetime
from pyramid.renderers import JSON


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    json_renderer = JSON()

    def datetime_adapter(obj, request):
        return obj.isoformat()

    json_renderer.add_adapter(datetime.datetime, datetime_adapter)
    config.add_renderer('json', json_renderer)

    config.add_route('generate_key', '/', request_method='GET')
    config.add_route('encrypt_file', '/encrypt_file', request_method='POST')
    config.add_route('decrypt_file', '/decrypt_file', request_method='POST')
    config.scan()
    return config.make_wsgi_app()
