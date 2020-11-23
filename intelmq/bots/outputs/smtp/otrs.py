# -*- coding: utf-8 -*-
import csv
import io
import smtplib
import ssl
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict

from intelmq.lib.bot import Bot


class SMTPOTRSOutputBot(Bot):

    template_dir = '/opt/var/templates'
    _warnings = []

    def init(self):
        if getattr(self.parameters, 'ssl', False):
            self.smtp_class = smtplib.SMTP_SSL
        else:
            self.smtp_class = smtplib.SMTP
        self.starttls = getattr(self.parameters, 'starttls', False)
        #self.fieldnames = getattr(self.parameters, 'fieldnames')
        #if isinstance(self.fieldnames, str):
        #    self.fieldnames = self.fieldnames.split(',')
        self.username = getattr(self.parameters, 'smtp_username', None)
        self.password = getattr(self.parameters, 'smtp_password', None)
        self.http_verify_cert = getattr(self.parameters, 'http_verify_cert',
                                        True)
        self.j2_env = Environment(loader=FileSystemLoader(self.template_dir), trim_blocks=True)

        try:
            self._warnings = [ x.strip() for x in getattr(self.parameters, 'warnings', []).split(',') ]
        except:
            raise ValueError('Could not parse one of configuration parameters.')

    def process(self):
        event = self.receive_message()

        template = event.get('classification.identifier', 'default')
        if not os.path.exists('{}/{}.j2'.format(self.template_dir,template)):
            template = 'default'

        default_event = defaultdict(lambda: 'N/A', event)

        template = self.j2_env.get_template('{}.j2'.format(template))
        body = template.render(ev=default_event)

        if self.http_verify_cert and self.smtp_class == smtplib.SMTP_SSL:
            kwargs = {'context': ssl.create_default_context()}
        else:
            kwargs = {}

        with self.smtp_class(self.parameters.smtp_host, self.parameters.smtp_port,
                             **kwargs) as smtp:
            if self.starttls:
                if self.http_verify_cert:
                    smtp.starttls(context=ssl.create_default_context())
                else:
                    smtp.starttls()
            if self.username and self.password:
                smtp.auth(smtp.auth_plain, user=self.username, password=self.password)
            msg = MIMEMultipart()
            if self.parameters.text:
                #msg.attach(MIMEText(self.parameters.text.format(ev=event)))
                msg.attach(MIMEText(body))
            msg['Subject'] = self.parameters.subject.format(ev=event)
            mail_from = "%s <%s>" % (event['extra.contacts'][0]['name'],event['extra.contacts'][0]['email'])
            #msg['From'] = self.parameters.mail_from.format(ev=event)
            #msg['From'] = mail_from
            msg['From'] = ','.join([ c['name'] + ' <' + c['email'] + '>' for c in event['extra.contacts'] ])
            #msg['To'] = self.parameters.mail_to.format(ev=event)
            msg['Bcc'] = self.parameters.mail_to.format(ev=event)
            msg['X-OTRS-DynamicField-IP'] = event['source.ip']
            url = event.get('extra.url', None) 
            if not url == None:
                msg['X-OTRS-DynamicField-URL'] = url
            queue = 'IntelMQ'
            identifier = event.get('classification.identifier', None)
            ctype = event.get('classification.type', None)
            promote = event.get('extra.promote', False)
            if ctype == 'ddos':
                queue = 'DDOS'
            if identifier == 'drone':
                queue = 'Incidents'
            if identifier in self._warnings:
                queue = 'Warning'
            if ctype != None:
                msg['X-OTRS-DynamicField-Type'] = ctype
                msg['X-OTRS-Type'] = ctype
            if identifier != None:
                msg['X-OTRS-DynamicField-Identifier'] = identifier
            if promote == True:
                msg['X-OTRS-DynamicField-Promote'] = 'YES'
            msg['X-OTRS-Queue'] = queue
            msg['X-OTRS-Title'] = event.get('feed.name', 'Other')
            smtp.send_message(msg, from_addr=self.parameters.mail_from,
                              to_addrs=self.parameters.mail_to.format(ev=event))

        self.acknowledge_message()


BOT = SMTPOTRSOutputBot

