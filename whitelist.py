import typing

from mitmproxy import ctx, exceptions, flowfilter, http, version

class Whitelist:
    def __init__(self):
        self.whitelist = []

    def load(self, loader):
        self.whitelist.append("google.com")
        self.whitelist.append("neverssl.com")

    def request(self, flow: http.HTTPFlow) -> None:
        #ctx.log.info("flow.request.url: {}".format(flow.request.url))
        killSession = True

        for domain in self.whitelist:
            if flow.request.pretty_host.endswith(domain):
                killSession = False

        if killSession:
            flow.kill()        

addons = [
    Whitelist()
]