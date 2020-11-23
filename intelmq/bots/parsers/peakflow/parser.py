# -*- coding: utf-8 -*-
"""
AlertTriggered Parser bot test
"""
import re

from intelmq.lib.bot import ParserBot, utils

class PeakflowBot(ParserBot):
    def init(self):
        if getattr(self.parameters, 'foobar', True):
            self.foobar = "Yes"
        else:
            self.foobar = "No"

    def parse(self, text):
        s = False
        level = 'other'
        year = '<noyear>'
        time = '<notime>'
        ip = '0.0.0.0'
        url = '<none>'

        for line in text.split("\n"):
          line = line.strip()
          t = re.match("Dos host detection alert started at (.+) (.+) CEST", line)
          if t:
            year = t.group(1)
            time = t.group(2)
            continue
          t = re.match("URL:\s+(.*)", line)
          if t:
            url = t.group(1)
            continue
          t = re.match("Host:\s+(.*)", line)
          if t:
            ip = t.group(1)
            continue
          t = re.match("Importance:\s+(.*)", line)
          if t:
            level = t.group(1)
            continue

        #2019-07-16T12:20:18+00:00
        observation = "{}T{}+00:00".format(year,time)

        # Return the fields
        return level, observation, ip, url

    def process(self):
        report = self.receive_message()
        text = utils.base64_decode(report["raw"])
        
        # parse the body
        level, time, ip, url = self.parse(text)
        self.logger.info("Peakflow parsed")

        event = self.new_event(report)
        event.add('raw', text)
        event.add('extra.body', text)
        event.add('extra.type', level)
        event.add('extra.url', url)
        event.add('source.ip', ip)
        event.add('classification.type', 'ddos')
        event.add('classification.identifier', 'ddos')
        event.add('feed.code', 'Peakflow', overwrite=True)
        event.add('feed.name', 'Peakflow', overwrite=True)
        event.add('time.observation', time, overwrite=True)
        self.send_message(event)
        self.acknowledge_message()


BOT = PeakflowBot

