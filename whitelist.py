import typing

from mitmproxy import ctx, exceptions, flowfilter, http, version

class Whitelist:
    def __init__(self):
        self.whitelist = []

    def load(self, loader):
        self.whitelist.append("https://www.google.com/")
        self.whitelist.append("http://neverssl.com/")

    def request(self, flow: http.HTTPFlow) -> None:
        #ctx.log.info("flow.request.url: {}".format(flow.request.url))
        if flow.request.url not in self.whitelist:
            ctx.log.info("flow.request.url: {}".format(flow.request.url))
            flow.kill()

        if flow.response or flow.error or (flow.reply and flow.reply.state == "taken"):
            return

addons = [
    Whitelist()
]