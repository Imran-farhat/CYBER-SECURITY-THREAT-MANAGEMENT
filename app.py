import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

class RequestHandler(BaseHTTPRequestHandler):
    # List of known threats with details and mitigation strategies
    known_threats = {
        "malware": {
            "severity": "High",
            "likelihood": "Likely",
            "description": "Malware refers to malicious software designed to harm or exploit any programmable device.",
            "mitigation": [
                "Install reputable antivirus software.",
                "Keep your operating system and software updated.",
                "Avoid downloading files from untrusted sources.",
                "Use a firewall to protect your network."
            ]
        },
        "phishing": {
            "severity": "Medium",
            "likelihood": "Possible",
            "description": "Phishing is a method of trying to gather personal information using deceptive emails and websites.",
            "mitigation": [
                "Verify the sender's email address before clicking links.",
                "Use email filtering tools.",
                "Educate users about recognizing phishing attempts.",
                "Enable multi-factor authentication on accounts."
            ]
        },
        "ransomware": {
            "severity": "Critical",
            "likelihood": "Likely",
            "description": "Ransomware is a type of malware that encrypts files on a device, rendering them inaccessible until a ransom is paid.",
            "mitigation": [
                "Regularly back up data to an external source.",
                "Use strong passwords and multi-factor authentication.",
                "Avoid clicking on suspicious links or attachments.",
                "Keep software updated with the latest security patches."
            ]
        },
        "spyware": {
            "severity": "Medium",
            "likelihood": "Unlikely",
            "description": "Spyware is software that secretly monitors user activity and collects personal information.",
            "mitigation": [
                "Use anti-spyware tools.",
                "Be cautious when installing software from unknown sources.",
                "Regularly check privacy settings on devices.",
                "Educate users about safe browsing practices."
            ]
        }
    }

    def do_GET(self):
        """Handles GET requests."""
        if self.path == '/':
            self.send_html_response('index.html')
        else:
            self.send_error_response(404, "Page not found")

    def do_POST(self):
        """Handles POST requests for threat detection."""
        if self.path == '/detectThreat':
            self.handle_threat_detection()
        else:
            self.send_error_response(404, "Invalid endpoint")

    def send_html_response(self, filename):
        """Sends an HTML response by reading a file."""
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(file.read().encode('utf-8'))
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.")
            self.send_error_response(404, "File not found")
        except Exception as e:
            print(f"Unexpected error: {e}")
            self.send_error_response(500, "Internal server error")

    def send_error_response(self, code, message):
        """Sends an error response with a custom message."""
        self.send_response(code)
        self.end_headers()
        self.wfile.write(json.dumps({'error': message}).encode('utf-8'))

    def handle_threat_detection(self):
        """Processes the threat detection request."""
        threat_type = self.get_post_data().get('type', '').lower()
        
        if threat_type in self.known_threats:
            details = self.known_threats[threat_type]
            result = {
                'threat_type': threat_type.capitalize(),
                'severity': details['severity'],
                'likelihood': details['likelihood'],
                'description': details['description'],
                'mitigation': details['mitigation']
            }
            self.send_json_response(result)
        else:
            self.send_json_response({'error': 'Unknown threat type.'})

    def get_post_data(self):
        """Parses the POST data from the request."""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        return {k: v[0] for k, v in parse_qs(post_data).items()}

    def send_json_response(self, response):
        """Sends a JSON response."""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('utf-8'))

def run(server_class=HTTPServer, handler_class=RequestHandler, port=8000):
    """Runs the HTTP server."""
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Serving on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    run()