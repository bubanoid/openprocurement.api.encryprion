from openprocurement_client.sync import get_tenders
from openprocurement_client.client import TendersClient
from .utils import decrypt_file

DEFAULT_API_HOST = 'https://lb.api-sandbox.openprocurement.org/'
DEFAULT_API_VERSION = '2.3'
DEFAULT_API_KEY = ''
DEFAULT_API_EXTRA_PARAMS = {
    'opt_fields': 'status', 'mode': '_all_'}

DEFAULT_RETRIEVERS_PARAMS = {
    'down_requests_sleep': 5,
    'up_requests_sleep': 1,
    'up_wait_sleep': 30,
    'queue_size': 101
}


def execute_tenders():
    tender_client = TendersClient(key=DEFAULT_API_KEY,
                                  host_url=DEFAULT_API_HOST,
                                  api_version=DEFAULT_API_VERSION)
    for t in get_tenders(host=DEFAULT_API_HOST,
                         version=DEFAULT_API_VERSION, key=DEFAULT_API_KEY,
                         extra_params=DEFAULT_API_EXTRA_PARAMS,
                         retrievers_params=DEFAULT_RETRIEVERS_PARAMS):
        if t.status == 'active.qualification':
            tender = tender_client.get_tender(t.id)
            bids = tender_client._get_tender_resource_list(tender, 'bids')
            for bid in bids:
                if 'documents' in bid:
                    for document in bid['documents']:
                        if 'secret_key' in document:
                            bid_file = tender_client.get_file(tender,
                                                              document['url'])
                            bid_decrypted_file = decrypt_file(
                                document.secret_key, bid_file)
                            doc_url = tender_client.update_bid_document(
                                bid_decrypted_file, tender, bid.id, document.id
                            )
                            document.url = doc_url['get_url']
            # tender.status = 'unsuccessful'
            new_tender = tender_client.patch_tender(tender)
            print new_tender
