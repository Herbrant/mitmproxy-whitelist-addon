FROM mitmproxy/mitmproxy
WORKDIR /app/
ADD whitelist.py .

EXPOSE 8080
ENTRYPOINT [ "mitmdump", "-s", "whitelist.py" ]