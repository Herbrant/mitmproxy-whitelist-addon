from os import path
from mitmproxy import ctx, http, net

class Rule:
    @staticmethod
    def parseOperation(ruleString: str) -> str:
        operation = ruleString[0]

        if operation != '+' and operation != '-':
            operation = '+'

        return operation

    @staticmethod
    def parseDomain(ruleString: str) -> str:
        index = ruleString.find("/")
        domain = ruleString
        
        if index != -1:
            domain = domain[:index]
        
        if domain[0] == '+' or domain[0] == '-':
            domain = domain[1:]

        return domain
    
    @staticmethod
    def parsePath(ruleString: str) -> str:
        index = ruleString.find("/")

        if index == -1:
            return "/"
        else:
            return ruleString[index:]

    def __init__(self, ruleString):
        ruleString = ruleString.replace(" ", "").replace("http://", "").replace("https://", "")

        self.operation = self.parseOperation(ruleString)
        self.domain = self.parseDomain(ruleString)
        self.path = self.parsePath(ruleString)

    def __str__(self):
        return "Operation: {} Domain: {} Path: {}".format(self.operation, self.domain, self.path)

class Whitelist:
    RULES_CONFIGURATION_FILE="/usr/local/mitmproxy/whitelist/rules"
    DEFAULT_CONTENT_FILE="/usr/local/mitmproxy/whitelist/block.html"

    def __init__(self):
        self.rules = []
    
    def loadRules(self):
        with open(self.RULES_CONFIGURATION_FILE) as rules:
            rules_text = list(filter(None, rules.read().split('\n')))
        
        for rule in rules_text:
            newRule = Rule(rule)
            ctx.log.info(newRule)
            self.rules.append(newRule)
    
    def load(self, loader):
        self.loadRules()
    
    @staticmethod
    def checkDomainRule(reqDomain: str, domain: str) -> bool:
        if reqDomain == domain:
            return True
        if reqDomain.endswith(domain) and reqDomain[:reqDomain.index(domain)][-1] == '.':
            return True
        return False
    
    @staticmethod
    def checkPathRule(reqPath: str, path: str) -> bool:
        if reqPath.startswith(path):
            return True
        return False

    def checkRequest(self, request: net.http.request.Request) -> bool:
        reqDomain = request.pretty_host
        reqPath = request.path

        admitted =  False

        for rule in self.rules:
            if rule.operation == '+':
                if self.checkDomainRule(reqDomain, rule.domain) and self.checkPathRule(reqPath, rule.path):
                    admitted = True
            elif rule.operation == '-':
                if self.checkDomainRule(reqDomain, rule.domain) and self.checkPathRule(reqPath, rule.path):
                    admitted = False
        
        return admitted

    def request(self, flow: http.HTTPFlow) -> None:
        ctx.log.info("[REQUEST] TYPE: {} DOMAIN: {} URL: {}".format(
            flow.request.method, flow.request.pretty_host, flow.request.pretty_url,
            flow.request.path)
        )

        if not self.checkRequest(flow.request):
            ctx.log.info("{} ADMITTED".format(flow.request.pretty_url))
            if (path.exists(self.DEFAULT_CONTENT_FILE)):
                with open(self.DEFAULT_CONTENT_FILE) as blockhtml:
                    content = blockhtml.read()
            else:
                content = "<html><h1>BLOCKED</h1></html>"
            flow.response = net.http.Response.make(
                200,
                content,
                {"Content-Type": "text/html"}
            )

    
    def error(self, flow: http.HTTPFlow) -> None:
        if (path.exists(self.DEFAULT_CONTENT_FILE)):
                with open(self.DEFAULT_CONTENT_FILE) as blockhtml:
                    content = blockhtml.read()
        else:
            content = "<html><h1>BLOCKED</h1></html>"
        
        flow.response = net.http.Response.make(
            200,
            content,
            {"Content-Type": "text/html"}
        )

addons = [
    Whitelist()
]