from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection


UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 18081
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 18082


class GuardHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.split("?", 1)[0].endswith(".cgi"):
            self.send_error(403, "CGI access disabled by lab compensating control")
            return

        upstream = HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=5)
        try:
            upstream.request("GET", self.path, headers={"Host": f"{UPSTREAM_HOST}:{UPSTREAM_PORT}"})
            response = upstream.getresponse()
            body = response.read()
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in {"connection", "content-length", "transfer-encoding"}:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            upstream.close()

    def log_message(self, format: str, *args: object) -> None:
        print(f"shellshock_guard: {self.address_string()} {format % args}", flush=True)


if __name__ == "__main__":
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), GuardHandler)
    print(f"shellshock_guard listening on http://{LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    server.serve_forever()
