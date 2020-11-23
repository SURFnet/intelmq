# -*- coding: utf-8 -*-
"""
AlertTriggered Parser bot test
"""
import re

from intelmq.lib.bot import ParserBot, utils

class AlertBot(ParserBot):
    def init(self):
        if getattr(self.parameters, 'foobar', True):
            self.foobar = "Yes"
        else:
            self.foobar = "No"

    def parse(self, text):
        s = False
        body = ''
        alert = 'other'
        time = '<notime>'
        ip = '0.0.0.0'

        for line in text.split("\n"):
          line = line.strip()
          t = re.match("Alert '(.+)' (.+),(.+),", line)
          if (t):
            alert = t.group(1)
            time = t.group(2)
            ip = t.group(3)
          if (re.match("Date first seen", line)):
            s = True
          if (re.match("Summary", line)):
            s = False
          if (s):
            body += line + "\n"
        
        #201907160300 ->
        #2019-07-16T12:20:18+00:00
        observation = "{}-{}-{}T{}:{}:00+00:00".format(time[:4], time[4:6], time[6:8], time[8:10], time[10:])
        return alert, observation, ip, body

    def process(self):
        report = self.receive_message()
        text = utils.base64_decode(report["raw"])
        alert, time, ip, body = self.parse(text)
        #self.logger.info("AlertBot: t:{}\nip: {}\ntext:{}\nbody:{}".format(time, ip, text, body))
        self.logger.info("AlertBot parsed")
        event = self.new_event(report)
        event.add('raw', text)
        event.add('extra.body', body)
        #event.add('extra.type', alert)
        event.add('source.ip', ip)
        event.add('feed.code', 'alert-triggered', overwrite=True)
        event.add('feed.name', 'Alert Triggered', overwrite=True)
        event.add('classification.type', 'ddos')
        event.add('classification.identifier', alert)
        event.add('time.source', time, overwrite=True)
        self.send_message(event)
        self.acknowledge_message()


BOT = AlertBot

