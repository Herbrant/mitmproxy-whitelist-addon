from os import path
from mitmproxy import ctx, http, net

class Rule:
    def __parseOperation(self, ruleString: str) -> str:
        operation = ruleString[0]

        if operation != '+' and operation != '-':
            operation = '+'

        return operation

    def __parseDomain(self, ruleString: str) -> str:
        index = ruleString.find("/")
        domain = ruleString
        
        if index != -1:
            domain = domain[:index]
        
        if domain[0] == '+' or domain[0] == '-':
            domain = domain[1:]

        return domain
    
    def __parsePath(self, ruleString) -> str:
        index = ruleString.find("/")

        if index == -1:
            return "/"
        else:
            return ruleString[index:]

    
    def __parseRuleString(self, ruleString):
        ruleString = ruleString.replace(" ", "").replace("http://", "").replace("https://", "")      
        operation = self.__parseOperation(ruleString)
        domains = self.__parseDomain(ruleString)
        path = self.__parsePath(ruleString)

        return operation, domains, path
        
        return 
    def __init__(self, ruleString):
        self.operation, self.domain, self.path = self.__parseRuleString(ruleString)

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
    
    def __checkDomainRule(self, reqDomain: str, domain: str) -> bool:
        if reqDomain == domain:
            return True
        if reqDomain.endswith(domain) and reqDomain[:reqDomain.index(domain)][-1] == '.':
            return True
        return False
    
    def __checkPathRule(self, reqPath: str, path: str) -> bool:
        if reqPath.startswith(path):
            return True
        return False

    def __checkRequest(self, request: net.http.request.Request) -> bool:
        reqDomain = request.pretty_host
        reqPath = request.path

        admitted =  False

        for rule in self.rules:
            if rule.operation == '+':
                if self.__checkDomainRule(reqDomain, rule.domain) and self.__checkPathRule(reqPath, rule.path):
                    admitted = True
            elif rule.operation == '-':
                if self.__checkDomainRule(reqDomain, rule.domain) and self.__checkPathRule(reqPath, rule.path):
                    admitted = False
        
        return admitted

    def request(self, flow: http.HTTPFlow) -> None:
        ctx.log.info("[REQUEST] TYPE: {} DOMAIN: {} URL: {}".format(
            flow.request.method, flow.request.pretty_host, flow.request.pretty_url,
            flow.request.path)
        )

        if not self.__checkRequest(flow.request):
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