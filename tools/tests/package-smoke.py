#!/usr/bin/env python3
"""Local disposable image smoke test; never publishes ports or images.

Requires Python 3 and an already running Podman/Docker. Builds only allowlisted
tracked sources (current working-tree versions); no private/runtime config.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import uuid
from urllib.parse import urljoin

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
parser.add_argument('--image', help='Use an already built local decision image')
parser.add_argument('--expect-missing-assets', action='store_true')
args = parser.parse_args()
engine = args.engine
prefix = 'fastgate-smoke-' + uuid.uuid4().hex[:10]
containers, images = [], []
network = prefix


def run(*argv, check=True):
    return subprocess.run([engine, *argv], check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=900 if argv[0] in ('build', 'pull') else 60)


def create(name, image, *command, env=(), alias=None):
    containers.append(name)
    run('create', '--name', name, '--network', network,
        *(['--network-alias', alias] if alias else []),
        *[item for pair in env for item in ('-e', pair)], image, *command)


REQUEST = '''import json,sys,urllib.request,urllib.error
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k): return None
url,body,headers=json.loads(sys.argv[1])
req=urllib.request.Request(url,data=None if body is None else json.dumps(body).encode(),headers=headers)
try: response=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(req,timeout=4)
except urllib.error.HTTPError as error: response=error
print(json.dumps([response.status,dict(response.headers),response.read().decode()]))
'''


def request(host, path, body=None, headers=None):
    headers = {'User-Agent': 'Mozilla/5.0 package-smoke', 'Accept-Language': 'en',
               'Content-Type': 'application/json', **(headers or {})}
    return json.loads(run('exec', origin, 'python', '-c', REQUEST,
                         json.dumps([f'http://{host}:8080{path}', body, headers])).stdout)


def wait_ready(host):
    for _ in range(40):
        try:
            if request(host, '/healthz')[0] == 200:
                return
        except (subprocess.CalledProcessError, ValueError):
            pass
        time.sleep(.25)
    raise AssertionError('listener did not start: ' + run('logs', host).stderr)


def build(context, dockerfile, tag):
    images.append(tag)
    result = run('build', '-t', tag, '-f', str(context / dockerfile), str(context), check=False)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    print('Built ' + tag, flush=True)


try:
    with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
        context = Path(tmp) / 'context'
        tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
        exact = {'decision-service/go.mod', 'decision-service/go.sum',
                 'decision-service/config.example.yaml', 'deploy/decision.Dockerfile',
                 'deploy/nginx.Dockerfile', 'edge-gateway/nginx.conf', '.dockerignore'}
        for name in tracked:
            if name in exact or (name.startswith('decision-service/') and name.endswith('.go')) or name in {
                'challenge-page/index.html', 'challenge-page/app.js', 'challenge-page/webauthn-solver.js'}:
                source = ROOT / name
                assert not source.is_symlink(), name
                target = context / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
        image = args.image or 'localhost/' + prefix
        if not args.image:
            build(context, 'deploy/decision.Dockerfile', image)
        run('network', 'create', '--internal', network)
        origin = prefix + '-origin'
        # Synthetic origin also runs the HTTP probe. No host listeners or real data.
        origin_code = '''from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import base64,hashlib,json
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.headers.get("Upgrade", "").lower() == "websocket":
   key=self.headers["Sec-WebSocket-Key"]+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
   self.send_response(101); self.send_header("Upgrade","websocket"); self.send_header("Connection","Upgrade")
   self.send_header("Sec-WebSocket-Accept",base64.b64encode(hashlib.sha1(key.encode()).digest()).decode())
   self.end_headers(); self.wfile.flush(); self.rfile.read(1); return
  self.send_response(200); self.end_headers(); self.wfile.write(json.dumps({"synthetic_origin":True,"path":self.path,"headers":dict(self.headers)}).encode())
ThreadingHTTPServer(("0.0.0.0",8081),Handler).serve_forever()
'''
        # Pull before entering the isolated network; only public base image retrieval.
        if run('image', 'inspect', 'docker.io/library/python:3.11-alpine', check=False).returncode:
            run('pull', 'docker.io/library/python:3.11-alpine')
        create(origin, 'docker.io/library/python:3.11-alpine', 'python', '-c', origin_code, alias='origin')
        run('start', origin)
        secret = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
        config = {'version': 'v1', 'server': {'listen': ':8080', 'read_timeout_ms': 5000, 'write_timeout_ms': 5000},
                  'modes': {'enforce': True},
                  'cookie': {'name': 'Clearance', 'path': '/', 'max_age_sec': 3600, 'same_site': 'Lax', 'secure': False, 'http_only': True},
                  'token': {'alg': 'HS256', 'issuer': 'package-smoke', 'keys': {'fixture': secret}, 'current_kid': 'fixture'},
                  'cluster': {'secret_key': secret},
                  'policy': {'ws_concurrency_limits': {'per_ip': 1}, 'challenge_threshold': 50, 'block_threshold': 100, 'paths': [{'pattern': '^/protected', 'base': 60}]},
                  'challenge': {'difficulty_bits': 12, 'ttl_sec': 60, 'nonce_rps_limit': 100},
                  'webauthn': {'enabled': False}, 'threat_intel': {'enabled': False},
                  'proxy': {'enabled': True, 'mode': 'integrated', 'origin': f'http://{origin}:8081', 'challenge_path': '/__uam'}}
        config_file = Path(tmp) / 'synthetic.json'
        config_file.write_text(json.dumps(config))  # JSON is valid YAML; no extra Python dependencies.

        def decision(suffix, extra_env=(), extra_args=(), alias=None):
            name = prefix + suffix
            create(name, image, '-config', '/tmp/synthetic.json', *extra_args, env=extra_env, alias=alias)
            run('cp', str(config_file), name + ':/tmp/synthetic.json')
            run('start', name)
            return name

        if args.expect_missing_assets:
            failed = decision('-baseline')
            code = run('wait', failed).stdout.strip()
            logs = run('logs', failed)
            assert code != '0' and 'failed to create challenge asset handler' in logs.stderr + logs.stdout
            print('REPRODUCED: original image fails integrated startup because challenge assets are absent.')
        else:
            app = decision('-integrated', extra_args=('-operator-listen', '127.0.0.1:9091'))
            wait_ready(app)
            packaged = run('exec', app, 'find', '/app', '-type', 'f').stdout.splitlines()
            assert set(packaged) == {'/app/config.yaml', '/app/challenge-page/index.html',
                                    '/app/challenge-page/app.js', '/app/challenge-page/webauthn-solver.js'}
            for asset in ('', 'app.js', 'webauthn-solver.js'):
                response = request(app, '/__uam/' + asset)
                assert response[0] == 200
                assert response[2] == (context / 'challenge-page' / (asset or 'index.html')).read_text()
            assert request(app, '/__uam/missing.js')[0] == 404
            assert request(app, '/protected')[0] == 302
            # Hold one real, synthetic WebSocket open and try forged identities.
            # All sockets stay on this disposable internal container network.
            ws_probe = r'''import base64,os,socket,sys
host=sys.argv[1]
sockets=[]
def handshake(extra):
 s=socket.create_connection((host,8080),timeout=4); sockets.append(s)
 message="GET /ws HTTP/1.1\r\nHost: "+host+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+base64.b64encode(os.urandom(16)).decode()+"\r\nUser-Agent: Mozilla/5.0\r\nAccept-Language: en\r\n"+extra+"\r\n"
 s.sendall(message.encode()); response=b""
 while b"\r\n\r\n" not in response:
  chunk=s.recv(4096)
  assert chunk, "socket closed before handshake response"
  response+=chunk
 return int(response.split()[1])
try:
 assert handshake("")==101
 for extra in ("", "X-Forwarded-For: 203.0.113.99\r\n", "X-Real-IP: 203.0.113.98\r\n", "X-Client-IP: 203.0.113.97\r\n", "X-Forwarded-For: garbage\r\n"):
  assert handshake(extra)==302, "forged header bypassed admission: "+extra
finally:
 for s in sockets: s.close()
'''
            run('exec', origin, 'python', '-c', ws_probe, app)
            print('PASS: held WebSocket admission cannot be bypassed by forged or malformed IP headers.', flush=True)

            spoof = {'X-Forwarded-For': '203.0.113.99', 'X-Client-IP': '203.0.113.99'}
            status, _, body = request(app, '/v1/challenge/nonce', {'return_url': '/protected'}, spoof)
            assert status == 200
            nonce = json.loads(body)
            claims = json.loads(base64.urlsafe_b64decode(nonce['challenge_id'].split('.')[1] + '=='))
            assert claims['ip'] != '203.0.113.99', 'untrusted forwarding headers affected challenge IP'
            raw = base64.urlsafe_b64decode(nonce['nonce'] + '==')
            solution = 0
            while int.from_bytes(hashlib.sha256(raw + struct.pack('>I', solution)).digest(), 'big') >> (256 - nonce['difficulty_bits']):
                solution += 1
            status, headers, _ = request(app, '/v1/challenge/complete', {
                'challenge_id': nonce['challenge_id'], 'nonce': nonce['nonce'],
                'solution': solution, 'return_url': '/protected'}, {'X-Forwarded-For': '198.51.100.2'})
            assert status == 302 and headers['Location'] == '/protected'
            cookie = headers['Set-Cookie'].split(';')[0]
            for supplied, expected in ((r'/\attacker.invalid/path', '/'),
                                       ('/%5Cattacker.invalid/path', '/'),
                                       ('/%2fattacker.invalid/path', '/'),
                                       ('/%zz', '/'),
                                       ('/safe/%23hash/%3Fquery?x=a%2Bb', '/safe/%23hash/%3Fquery?x=a%2Bb')):
                # NoRedirect captures Location without navigating anywhere.
                status, redirected, _ = request(app, '/v1/challenge/complete', {
                    'challenge_id': nonce['challenge_id'], 'nonce': nonce['nonce'],
                    'solution': solution, 'return_url': supplied})
                assert status == 302 and redirected['Location'] == expected
            print('PASS: PoW completion rejects external/malformed paths and preserves safe escaping.', flush=True)

            status, _, body = request(app, '/protected', headers={'Cookie': cookie, **spoof})
            assert status == 200 and json.loads(body)['synthetic_origin']
            for path in ('/metrics', '/admin/stats'):
                assert request(app, path, headers={'Cookie': cookie, **spoof})[0] == 404
                run('exec', app, 'wget', '-qO', '/dev/null', 'http://127.0.0.1:9091' + path)
            # Operator listener must not be reachable through the container network.
            unreachable = run('exec', origin, 'python', '-c',
                              'import socket,sys; s=socket.socket(); s.settimeout(2); sys.exit(0 if s.connect_ex((sys.argv[1],9091)) else 1)', app, check=False)
            assert unreachable.returncode == 0
            for suffix, env, flags, error in (
                ('-missing', ('CHALLENGE_PAGE_DIR=/absent',), (), 'failed to create challenge asset handler'),
                ('-operator-invalid', (), ('-operator-listen', '0.0.0.0:9091'), 'invalid operator listener')):
                failed = decision(suffix, env, flags)
                assert run('wait', failed).stdout.strip() != '0'
                logs = run('logs', failed)
                assert error in logs.stdout + logs.stderr
            run('stop', '--time', '40', app)
            assert run('inspect', '--format', '{{.State.ExitCode}}', app).stdout.strip() == '0'
            logs = run('logs', app)
            assert 'shutdown complete' in logs.stdout + logs.stderr
            print('PASS: integrated assets, nonce/PoW/clearance/origin, spoof denial, isolated operator listener, missing assets, clean shutdown.', flush=True)
            # A separately configured synthetic trusted peer must still be honored.
            origin_info = json.loads(run('inspect', origin).stdout)[0]
            origin_ip = origin_info['NetworkSettings']['Networks'][network]['IPAddress']
            config['server']['trusted_proxies'] = [origin_ip + '/32']
            config_file.write_text(json.dumps(config))
            trusted = decision('-trusted')
            wait_ready(trusted)
            status, _, body = request(trusted, '/v1/challenge/nonce', {}, spoof)
            assert status == 200
            claims = json.loads(base64.urlsafe_b64decode(json.loads(body)['challenge_id'].split('.')[1] + '=='))
            assert claims['ip'] == '203.0.113.99'
            del config['server']['trusted_proxies']
            print('PASS: explicitly trusted synthetic proxy preserves forwarded client IP.', flush=True)
            # The separate NGINX mode must still own and serve its challenge assets.
            config['proxy']['enabled'] = False
            config_file.write_text(json.dumps(config))
            backend = decision('-decision', ('CHALLENGE_PAGE_DIR=/absent',), alias='decision')
            wait_ready(backend)
            assert request(backend, '/v1/authz', headers={'X-Original-URI': '/protected'})[0] == 401
            assert request(backend, '/metrics')[0] == 404
            nginx_image = 'localhost/' + prefix + '-nginx'
            build(context, 'deploy/nginx.Dockerfile', nginx_image)
            edge = prefix + '-nginx'
            create(edge, nginx_image)
            run('start', edge)
            # NGINX has no /healthz endpoint; use an allowed origin route for readiness.
            for _ in range(40):
                try:
                    if request(edge, '/')[0] == 200:
                        break
                except (subprocess.CalledProcessError, ValueError):
                    pass
                time.sleep(.25)
            else:
                logs = run('logs', edge)
                raise AssertionError(logs.stdout + logs.stderr)
            assert request(edge, '/protected')[0] == 302
            page_path = '/__uam?u=/protected'
            response = request(edge, page_path)
            if response[0] in (301, 302, 307, 308):
                page_path = response[1]['Location']
                if page_path.startswith('http'):
                    from urllib.parse import urlsplit
                    parsed = urlsplit(page_path)
                    page_path = parsed.path + ('?' + parsed.query if parsed.query else '')
                assert 'u=/protected' in page_path
                response = request(edge, page_path)
            assert response[0] == 200 and response[2] == (context / 'challenge-page/index.html').read_text()
            for asset in ('app.js', 'webauthn-solver.js'):
                response = request(edge, urljoin(page_path, asset))
                assert response[0] == 200 and response[2] == (context / 'challenge-page' / asset).read_text(), 'NGINX page script not served: ' + asset
            assert request(edge, '/__uam/missing.js')[0] == 404
            status, _, body = request(edge, '/protected', headers={'Cookie': cookie})
            assert status == 200 and json.loads(body)['synthetic_origin']
            assert request(edge, '/v1/challenge/nonce', {'return_url': '/protected'})[0] == 200
            print('PASS: NGINX-owned index/scripts, missing asset, auth_request redirect/clearance/origin, same-origin nonce API.', flush=True)

finally:
    for container in reversed(containers):
        run('rm', '-f', container, check=False)
    run('network', 'rm', network, check=False)
    for image in reversed(images):
        run('rmi', image, check=False)
