# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import logging

from werkzeug import urls

from odoo import api, fields, models, _
from odoo.addons.payment.models.payment_acquirer import ValidationError
from odoo.addons.payment_ccavenue.models.ccavutil import encrypt
from odoo.addons.payment_ccavenue.controllers.main import CCAvenueController
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

    def _ccavenue_request_parameters(self, values):
        keys = 'merchant_id+order_id+currency+amount+redirect_url+cancel_url+language'.split('+')
        param = ''.join('%s=%s&' % (k, values.get(k)) for k in keys)
        return param

    @api.multi
    def ccavenue_form_generate_values(self, values):
        self.ensure_one()
        base_url = self.env['ir.config_parameter'].get_param('web.base.url')
        ccavenue_values = dict(values,
                               access_code=self.ccavenue_access_code,
                               merchant_id=self.ccavenue_merchant_id,
                               order_id=values.get('reference'),
                               currency=values.get('currency').name,
                               amount=values.get('amount'),
                               redirect_url='%s' % urls.url_join(base_url, CCAvenueController._return_url),
                               cancel_url='%s' % urls.url_join(base_url, CCAvenueController._cancel_url),
                               language='EN',
                               )
        ccavenue_request_param = self._ccavenue_request_parameters(ccavenue_values)
        ccavenue_values['encRequest'] = encrypt(ccavenue_request_param, self.ccavenue_working_key)
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
            self.write({'acquirer_reference': data.get('tracking_id')})
            self._set_transaction_done()
            return True
        elif status_code == "Aborted":
            _logger.info('Aborted CCAvenue payment for tx %s: set as cancel' % (self.reference))
            self.write({'acquirer_reference': data.get('tracking_id'), 'state_message': data.get('status_message')})
            self._set_transaction_cancel()
            return False
        else:
            error = data.get('failure_message') or data.get('status_message')
            _logger.info(error)
            self._set_transaction_error(error)
            return False
