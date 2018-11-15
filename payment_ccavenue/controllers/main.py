# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import logging
import pprint
import werkzeug

from odoo.addons.payment_ccavenue.models.ccavutil import decrypt
from odoo import http
from odoo.http import request

_logger = logging.getLogger(__name__)


class CCAvenueController(http.Controller):
    _return_url = '/payment/ccavenue/return/'
    _cancel_url = '/payment/ccavenue/cancel/'

    @http.route(['/payment/ccavenue/return', '/payment/ccavenue/cancel'], type='http', auth='public', csrf=False)
    def ccavenue_return(self, return_url=False, **post):
        _logger.info('CCAvenue: Entering form_feedback with post data %s', pprint.pformat(post))
        if post:
            PaymentAcquirer = request.env['payment.acquirer']
            workingKey = PaymentAcquirer.search([('provider', '=', 'ccavenue')], limit=1).ccavenue_working_key
            result = decrypt(post.get('encResp'), workingKey)
            post_result = {}
            vals = result.split('&')
            for data in vals:
                temp = data.split('=')
                post_result[temp[0]] = temp[1]
            request.env['payment.transaction'].sudo().form_feedback(post_result, 'ccavenue')
        return werkzeug.utils.redirect('/payment/process')
