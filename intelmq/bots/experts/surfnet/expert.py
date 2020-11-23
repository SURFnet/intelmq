# -*- coding: utf-8 -*-
"""
SURFnet Expert bot test
$SHADOW_ALLOWED_ASN = array("1101","1103","1104","1125","1128","1132","1133","1139","1145","1161","1837","1888","25182");
$SHADOW_UNWANTED_CIDRS = ['192.42.116.0/27','145.220.137.0/24','192.42.116.41/32', '192.42.119.41/32'];
$SHADOW_UNWANTED_TYPE = array('cc_ip','cwsandbox_url','scan_http', 'scan_rsync', 'scan_afp', 'scan_ftp');
$SHADOW_UNWANTED_SUBTYPE = array('dnschanger','spam','sinkhole','B54-BASE','spamhaus.org','torstatus.blutmagie.de','spamcannibal.org','tor-node');
"""
import sys
import ipaddress

from intelmq.lib.bot import Bot

try:
    import psycopg2
except ImportError:
    psycopg2 = None

class SURFnetBot(Bot):

    _conn = None
    _cur = None
    _allowed_asns = []
    _unwanted_cidrs = []
    _unwanted_types = []
    _unwanted_identifiers = []
    _unwanted_subtypes = []

    def init(self):
        self.logger.debug("Start SURFnet DB Expert")
        if psycopg2 is None:
            raise ValueError('Could not import psycopg2. Please install it.')
        self._conn = psycopg2.connect(dbname="surfcert", user="surfcert", password="3dyZMzYBKdWNnCtX", host="otrs.surfcert.nl")
        self._cur = self._conn.cursor()

        try:
            self._allowed_asns = [ int(x) for x in getattr(self.parameters, 'allowed_asns', []).split(',') ]
            self._unwanted_cidrs = [ ipaddress.ip_network(x.strip()) for x in getattr(self.parameters, 'unwanted_cidrs', []).split(',') ]
            self._unwanted_types = [ x.strip() for x in getattr(self.parameters, 'unwanted_types', []).split(',') ]
            self._unwanted_identifiers = [ x.strip() for x in getattr(self.parameters, 'unwanted_identifiers', []).split(',') ]
            self._unwanted_subtypes = [ x.strip() for x in getattr(self.parameters, 'unwanted_subtypes', []).split(',') ]
            self._auto_promote = [ x.strip() for x in getattr(self.parameters, 'auto_promote', []).split(',') ]
        except:
            raise ValueError('Could not parse one of configuration parameters.')

        self.logger.debug("Allowed ASN's {}".format(self._allowed_asns))
        self.logger.debug("Unwanted CIDR's {}".format(self._unwanted_cidrs))
        self.logger.debug("Unwanted Types {}".format(self._unwanted_types))
        self.logger.debug("Unwanted Identifiers {}".format(self._unwanted_identifiers))
        self.logger.debug("Unwanted Subtypes {}".format(self._unwanted_subtypes))
        self.logger.debug("Auto promote {}".format(self._auto_promote))

    def process(self):
        event = self.receive_message()

        client_ip = ipaddress.ip_address(event.get('source.ip'))
        asn = event.get('source.asn', None)
        ctype = event.get('classification.type', None)
        identifier = event.get('classification.identifier', None)
        subtype = None

        reason = ''
        unwanted = False
        for cidr in self._unwanted_cidrs:
            if client_ip in cidr:
                unwanted = True
                reason += "cidr match"

        if not asn in self._allowed_asns:
            unwanted = True
            reason += " ASN not allowed"

        if ctype in self._unwanted_types:
            unwanted = True
            reason += " Unwanted type"

        if identifier in self._unwanted_identifiers:
            unwanted = True
            reason += " Unwanted identifier"

        if subtype in self._unwanted_subtypes:
            unwanted = True
            reason += " Unwanted subtype"

        if identifier in self._auto_promote:
            event.add('extra.promote', True)

        if unwanted:
            self.logger.debug("Skipping event, reason: {}".format(reason))
        else:
            self.logger.debug("client_ip: %s in SURFnet ASN" % client_ip)

            contacts = []
            contact = { 'name': None, 'mail': [], 'dgc': [] }

            # Find client for client_ip
            query  = "SELECT contact, email, doelgroepcode FROM prefixes p JOIN contacts c ON p.customerid = c.customerid "
            query += "WHERE prefix >> '%s';" % client_ip

            (name, email, dgc) = ("None", "None", "None")

            self._cur.execute(query)
            rows = self._cur.fetchall()
            if len(rows):
                for row in rows:
                    #self.logger.debug("row: {}".format(row))
                    (name, email, dgc) = row
                    #email = "john@doe.net" # Temporarily overwrite mailaddress
                    contacts.append({'name': name, 'email': email, 'dgc': dgc})
            else:
                contacts.append({'name': name, 'email': email, 'dgc': dgc})

            self.logger.debug("name: %s, email: %s" % (name, email))
            event.add('extra.contacts', contacts)

            self.send_message(event)

        self.acknowledge_message()


BOT = SURFnetBot

