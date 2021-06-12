from sys import path
import typing
import argparse
from mitmproxy import ctx, http

class Whitelist:
    DOMAINS_CONFIGURATION_FILE="/usr/local/mitmproxy/whitelist/domains"
    URLS_CONFIGURATION_FILE="/usr/local/mitmproxy/whitelist/urls"

    def __init__(self):
        self.allowedDomains = []
        self.allowedUrls = []
    
    def loadDomains(self):
        with open(self.DOMAINS_CONFIGURATION_FILE) as domains:
            self.allowedDomains = list(filter(None, domains.read().split('\n')))
    
    def loadUrls(self):
        with open(self.URLS_CONFIGURATION_FILE) as urls:
            self.allowedUrls = list(filter(None, urls.read().split('\n')))

    def loadConfigFiles(self):
        self.loadDomains()
        self.loadUrls()
    
    def load(self, loader):
        self.loadConfigFiles()
        ctx.log.info("Allowed Domain List: {}".format(self.allowedDomains))
        ctx.log.info("Allowed Urls List: {}".format(self.allowedUrls))

    def request(self, flow: http.HTTPFlow) -> None:
        killSession = True

        for domain in self.allowedDomains:
            if flow.request.pretty_host.endswith(domain):
                killSession = False

        if killSession:
            flow.kill()        

addons = [
    Whitelist()
]