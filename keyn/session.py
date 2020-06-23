from keyn import api, crypto
import pyqrcode
import qrcode
from keyn.queue_handler import QueueHandler


class Session:

    def __init__(self):
        # Check if session already exists, if so create from that
        # Else check if pairing variables already exist
        # Else create new pairing vars.
        # seed = crypto.generate_seed(32)
        # pairing_queue_seed = crypto.to_base64(seed)
        # pairing_keypair = crypto.create_signing_keypair(seed)
        # TODO: Save pairing data
        # keypair = crypto.generate_keypair()
        # print(keypair)
        # print(pairing_queue_seed)
        pass

    def pairing_status(self):
        return

    def pair(self):
        seed = crypto.generate_seed(32)
        pairing_queue_seed = crypto.to_base64(seed)
        pairing_keypair = crypto.create_signing_keypair(seed)
        # TODO: Save pairing data
        priv_key, pub_key = crypto.generate_keypair()
        api.create_pairing_queue(pairing_keypair)
        url = '%s/%s/%s/%s/%s' % (api.API_URL, api.ENV, 'sessions',
                                  crypto.to_base64(pairing_keypair.verify_key.__bytes__()), 'pairing')
        queue_handler = QueueHandler(pairing_keypair, url)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data('https://keyn.app/pair?p=%s&q=%s&b=%s&o=%s&v=1' % (pub_key, pairing_queue_seed, 'cli', 'Mac%20OS'))
        qr.make(fit=True)
        qr.print_ascii()
        messages = queue_handler.start(True)
        for message in messages:
            data = message["body"]
            print(data)
            # verify with pairing_pub_key
            # decryptAnonymous with priv_key
            # parse JSON
            # Verify content
            # Generate shared key
            # Save data
            # Delete pairing queue
            # Initialize session object (should this be static?)