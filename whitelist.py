import os, json
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
    CONFIG_FILE="/usr/local/mitmproxy/whitelist/config.json"
    LOG_FOLDER=os.path.expanduser("~") + "/.mitmproxy/"

    def __init__(self):
        self.rules = []
        self.redirectUrl = ""
        self.allowAll = False
        self.errorPageBody = "<h1>BLOCKED</h1>"
    
    def loadRules(self, jsonRules) -> None:
        for rule in jsonRules:
            newRule = Rule(rule)

            if newRule.domain == "*":
                self.allowAll = True
                ctx.log.info("MODE: Allow all requests")
                return
            else:
                self.rules.append(newRule)
        
        for rule in self.rules:
            ctx.log.info(rule)
    
    def loadConfig(self):
        with open(self.CONFIG_FILE) as config:
            data = json.load(config)
        
        if 'redirect_url' in data:
            self.redirectUrl = data['redirect_url']
            ctx.log.info("redirect url: {}".format(self.redirectUrl))
        
        if 'rules' in data:
            self.loadRules(data['rules'])

        if 'errorpage_body' in data:
            self.errorPageBody = data['errorpage_body']

    
    def load(self, loader):
        self.loadConfig()
    
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


    def __blockRequest(self, flow: http.HTTPFlow) -> None:
        if self.redirectUrl != '':
            flow.request.url = self.redirectUrl
            flow.request.url = Rule.parseDomain(self.redirectUrl)
            return
            
        content = "<html>" + self.errorPageBody +"</html>"

        flow.response = http.HTTPResponse.make(
            200,
            content,
            {"Content-Type": "text/html"}
        )
    
    def __logRequest(self, request: net.http.request.Request) -> None:
        currentTime = datetime.now().strftime("%D %H:%M:%S")

        logtext = "[{}] TYPE: {} URL: {}\n".format(currentTime, request.method, request.pretty_url)
        ctx.log.info(logtext)

        if not os.path.exists(self.LOG_FOLDER):
            os.makedirs(self.LOG_FOLDER)

        logPath = self.LOG_FOLDER + "log"

        with open(logPath, "a+") as logfile:
            logfile.write(logtext)


    def request(self, flow: http.HTTPFlow) -> None:
        self.__logRequest(flow.request)

        if not self.checkRequest(flow.request):
            self.__blockRequest(flow)
    
    def error(self, flow: http.HTTPFlow) -> None:
        self.__blockRequest(flow)

addons = [
    Whitelist()
]