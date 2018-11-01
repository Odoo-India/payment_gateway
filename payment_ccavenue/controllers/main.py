# -*- coding: utf-8 -*-

import logging
import pprint
import werkzeug

from odoo import http
from odoo.http import request

_logger = logging.getLogger(__name__)


class CCAvenueController(http.Controller):

    @http.route(['/payment/ccavenue/return', '/payment/ccavenue/cancel'], type='http', auth='public', csrf=False)
    def ccavenue_return(self, return_url=False, **post):
        _logger.info('CCAvenue: Entering form_feedback with post data %s', pprint.pformat(post))
        if post:
            PaymentAcquirer = request.env['payment.acquirer']
            key = PaymentAcquirer.search([('provider', '=', 'ccavenue')], limit=1).ccavenue_working_key
            post = PaymentAcquirer._ccavenue_encrypted_response(post, key)
            request.env['payment.transaction'].sudo().form_feedback(post, 'ccavenue')
        return werkzeug.utils.redirect(return_url or "/")
