# -*- coding: utf-8 -*-

import logging
import base64

from Crypto.Cipher import AES
from hashlib import md5
from werkzeug import urls

from odoo import api, fields, models, _
from odoo.addons.payment.models.payment_acquirer import ValidationError
from odoo.tools.float_utils import float_compare

_logger = logging.getLogger(__name__)


class PaymentAcquirer(models.Model):
    _inherit = 'payment.acquirer'

    provider = fields.Selection(selection_add=[('ccavenue', 'CCAvenue')])
    ccavenue_merchant_id = fields.Char(string='Merchant ID', required_if_provider='ccavenue')
    ccavenue_access_code = fields.Char(string='Access Code', required_if_provider='ccavenue')
    ccavenue_working_key = fields.Char(string='Working Key', required_if_provider='ccavenue')

    def _get_feature_support(self):
        """Get advanced feature support by provider.

        Each provider should add its technical in the corresponding
        key for the following features:
            * fees: support payment fees computations
            * authorize: support authorizing payment (separates
                         authorization and capture)
            * md5 decryption : support saving payment data by md5 decryption
        """
        res = super(PaymentAcquirer, self)._get_feature_support()
        res['fees'].append('ccavenue')
        return res

    def _get_ccavenue_urls(self, environment):
        """ CCAvenue URLs"""
        if environment == 'prod':
            return {'ccavenue_form_url': 'https://secure.ccavenue.com/transaction/transaction.do?command=initiateTransaction'}
        else:
            return {'ccavenue_form_url': 'https://test.ccavenue.com/transaction/transaction.do?command=initiateTransaction'}

    def ccavenue_pad(self, data):
        length = 16 - (len(data) % 16)
        data += chr(length)*length
        return data

    def _ccavenue_encrypted_request(self, values):
        iv = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        keys = 'merchant_id+order_id+currency+amount+redirect_url+cancel_url+language'.split('+')
        sign = ''.join('%s=%s&' % (k, values.get(k)) for k in keys)
        plainText = self.ccavenue_pad(sign)
        enc_cipher = AES.new(md5(self.ccavenue_working_key.encode()).hexdigest(), AES.MODE_CBC, iv)
        encryptedText = base64.b64encode(enc_cipher.encrypt(plainText))
        return encryptedText

    def _ccavenue_encrypted_response(self, values, key):
        dncryptedText = {}
        iv = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        encryptedText = values.get('encResp').decode('hex')
        dec_cipher = AES.new(md5(key).hexdigest(), AES.MODE_CBC, iv)
        result = base64.b64encode(dec_cipher.decrypt(encryptedText))
        vals = result.split('&')
        for data in vals:
            temp = data.split('=')
            dncryptedText[temp[0]] = temp[1]
        return dncryptedText

    @api.multi
    def ccavenue_form_generate_values(self, values):
        self.ensure_one()
        base_url = self.env['ir.config_parameter'].get_param('web.base.url')
        ccavenue_values = dict(values,
                               access_code=self.ccavenue_access_code,
                               merchant_id=self.ccavenue_merchant_id,
                               order_id=values.get('reference'),
                               currency=values.get('currency'),
                               amount=values.get('amount'),
                               redirect_url='%s' % urls.url_join(base_url, '/payment/ccavenue/return') + "?return_url=" + str(values.get('return_url')),
                               cancel_url='%s' % urls.url_join(base_url, '/payment/ccavenue/cancel'),
                               language='EN',
                               )

        ccavenue_values['encRequest'] = self._ccavenue_encrypted_request(ccavenue_values)
        return ccavenue_values

    @api.multi
    def ccavenue_get_form_action_url(self):
        self.ensure_one()
        return self._get_ccavenue_urls(self.environment)['ccavenue_form_url']


class PaymentTransaction(models.Model):
    _inherit = 'payment.transaction'

    @api.model
    def _ccavenue_form_get_tx_from_data(self, data):
        """ Given a data dict coming from ccavenue, verify it and find the related
        transaction record. """
        reference = data.get('order_id')
        if not reference:
            raise ValidationError(_('CCAvenue: received data with missing reference (%s)') % (reference))

        transaction = self.search([('reference', '=', reference)])
        if not transaction or len(transaction) > 1:
            error_msg = _('CCAvenue: received data for reference %s') % (reference)
            if not transaction:
                error_msg += _('; no order found')
            else:
                error_msg += _('; multiple order found')
            raise ValidationError(error_msg)
        return transaction

    @api.model
    def _ccavenue_form_get_invalid_parameters(self, data):
        invalid_parameters = []

        if self.acquirer_reference and data.get('order_id') != self.acquirer_reference:
            invalid_parameters.append(
                ('Transaction Id', data.get('order_id'), self.acquirer_reference))
        # check what is buyed
        if float_compare(float(data.get('amount', '0.0')), self.amount, 2) != 0:
            invalid_parameters.append(('Amount', data.get('amount'), '%.2f' % self.amount))

        return invalid_parameters

    @api.model
    def _ccavenue_form_validate(self, data):
        if self.state == 'done':
            _logger.warning('CCAvenue: trying to validate an already validated tx (ref %s)' % self.reference)
            return True
        status_code = data.get('order_status')
        if status_code == "Success":
            _logger.info('Validated CCAvenue payment for tx %s: set as done' % (self.reference))
            self.write({
                'state': 'done',
                'acquirer_reference': data.get('tracking_id'),
                'date_validate': fields.Datetime.now(),
            })
            return True
        elif status_code == "Aborted":
            _logger.info('Aborted CCAvenue payment for tx %s: set as cancel' % (self.reference))
            self.write({
                'state': 'cancel',
                'acquirer_reference': data.get('tracking_id'),
                'date_validate': fields.Datetime.now(),
            })
            return True
        else:
            error = data.get('failure_message')
            _logger.info(error)
            self.write({
                'state': 'error',
                'state_message': error,
            })
            return False
