import os
from mitmproxy import ctx, http, net
from datetime import datetime

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
    LOG_FOLDER=os.path.expanduser("~") + "/.mitmproxy/"

    def __init__(self):
        self.rules = []
        self.allowAll = False
    
    def loadRules(self):
        with open(self.RULES_CONFIGURATION_FILE) as rules:
            rules_text = list(filter(None, rules.read().split('\n')))
        
        for rule in rules_text:
            newRule = Rule(rule)

            if newRule.domain == "*":
                self.allowAll = True
                ctx.log.info("MODE: Allow all requests")
                return
            else:
                self.rules.append(newRule)
        
        for rule in self.rules:
            ctx.log.info(rule)
            

    
    def load(self, loader):
        self.loadRules()
    
    @staticmethod
    def checkDomainRule(reqDomain: str, domain: str) -> bool:
        if reqDomain == domain:
            return True
        return False
    
    @staticmethod
    def checkPathRule(reqPath: str, path: str) -> bool:
        if reqPath.startswith(path):
            return True
        return False

    def checkRequest(self, request: net.http.request.Request) -> bool:
        if self.allowAll:
            return True

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

    def __errorPage(self, flow: http.HTTPFlow) -> None:
        if os.path.exists(self.DEFAULT_CONTENT_FILE):
                with open(self.DEFAULT_CONTENT_FILE) as blockhtml:
                    content = blockhtml.read()
        else:
            content = "<html><h1>BLOCKED</h1></html>"

        flow.response = http.HTTPResponse.make(
            200,
            content,
            {"Content-Type": "text/html"}
        )
    
    def __logRequest(self, request: net.http.request.Request) -> None:
        currentTime = datetime.now().strftime("%D %H:%M:%S")

        logtext = "[{}] TYPE: {} URL: {}".format(currentTime, request.method, request.pretty_url)
        ctx.log.info(logtext)

        if not os.path.exists(self.LOG_FOLDER):
            os.makedirs(self.LOG_FOLDER)

        logPath = self.LOG_FOLDER + "log"

        with open(logPath, "a+") as logfile:
            logfile.write(logtext)


    def request(self, flow: http.HTTPFlow) -> None:
        self.__logRequest(flow.request)

        if not self.checkRequest(flow.request):
            self.__errorPage(flow)
    
    def error(self, flow: http.HTTPFlow) -> None:
        self.__errorPage(flow)

addons = [
    Whitelist()
]