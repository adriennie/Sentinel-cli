#!/usr/bin/env python3
"""Real pinned Claude client, synthetic localhost Messages API; no model service calls."""
import argparse
import http.server
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import threading

VERSION = '2.1.304'

def run_fixture(sentinel, claude):
    with tempfile.TemporaryDirectory(prefix='sentinel-provider-') as folder:
        directory = Path(folder).resolve()
        project = directory / 'project'
        project.mkdir()
        config = directory / 'claude-config'
        config.mkdir()
        subprocess.run([str(sentinel), 'init', '--project', str(project)], check=True, capture_output=True)
        subprocess.run([str(sentinel), 'agent', 'setup', 'claude', '--project', str(project)], check=True, capture_output=True)
        original_policy = (project / 'sentinel.yml').read_bytes()
        calls = []
        offered = set()
        targets = [('allowed', project / 'src' / 'allowed.txt'), ('denied', project / 'sentinel.yml'), ('approved', project / 'src' / 'auth' / 'approved.txt')]
        phase = [0]
        class Server(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                length = int(self.headers.get('Content-Length', 0))
                if length > 16 * 1024 * 1024:
                    self.send_error(413)
                    return
                body = json.loads(self.rfile.read(length))
                if 'count_tokens' in self.path:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"input_tokens": 10}')
                    return
                calls.append(body)
                # Requests from auxiliary background features receive no tool calls.
                name, target = targets[phase[0]]
                tool_id = 'toolu_sentinel_' + name
                already = any(any(v.get('type') == 'tool_use' and v.get('id') == tool_id for v in m.get('content', []) if isinstance(v, dict)) for m in body.get('messages', []) if isinstance(m.get('content'), list))
                retry_id = tool_id + '_retry'
                retry_done = any(any(v.get('type') == 'tool_use' and v.get('id') == retry_id for v in m.get('content', []) if isinstance(v, dict)) for m in body.get('messages', []) if isinstance(m.get('content'), list))
                if name == 'approved' and already and not retry_done:
                    listing = subprocess.run([str(sentinel), 'approvals', 'list', '--project', str(project), '--format=json'], capture_output=True, text=True, check=True)
                    pending = next(a for a in json.loads(listing.stdout)['data']['result'] if a['status'] == 'pending' and 'src/auth/approved.txt' in a['paths'])
                    subprocess.run([str(sentinel), 'approvals', 'grant', pending['id'], '--binding', pending['binding'], '--project', str(project)], capture_output=True, check=True)
                    content = [{'type': 'tool_use', 'id': retry_id, 'name': 'Write', 'input': {'file_path': str(target), 'content': 'SYNTHETIC FIXTURE ONLY\n'}}]
                    reason = 'tool_use'
                elif not already:
                    offered.add(name)
                    content = [{'type': 'tool_use', 'id': tool_id, 'name': 'Write', 'input': {'file_path': str(target), 'content': 'SYNTHETIC FIXTURE ONLY\n'}}]
                    reason = 'tool_use'
                else:
                    content = [{'type': 'text', 'text': 'Synthetic fixture complete.'}]
                    reason = 'end_turn'
                response = {'id': 'msg_sentinel_fixture', 'type': 'message', 'role': 'assistant', 'model': body.get('model', 'fixture'), 'content': content, 'stop_reason': reason, 'stop_sequence': None, 'usage': {'input_tokens': 10, 'output_tokens': 10}}
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream' if body.get('stream') else 'application/json')
                self.end_headers()
                if not body.get('stream'):
                    self.wfile.write(json.dumps(response).encode())
                    return
                def event(kind, payload):
                    self.wfile.write(('event: ' + kind + '\ndata: ' + json.dumps(payload) + '\n\n').encode())
                start = dict(response, content=[], stop_reason=None)
                event('message_start', {'type': 'message_start', 'message': start})
                for index, block in enumerate(content):
                    if block['type'] == 'tool_use':
                        event('content_block_start', {'type': 'content_block_start', 'index': index, 'content_block': dict(block, input={})})
                        event('content_block_delta', {'type': 'content_block_delta', 'index': index, 'delta': {'type': 'input_json_delta', 'partial_json': json.dumps(block['input'])}})
                    else:
                        event('content_block_start', {'type': 'content_block_start', 'index': index, 'content_block': {'type': 'text', 'text': ''}})
                        event('content_block_delta', {'type': 'content_block_delta', 'index': index, 'delta': {'type': 'text_delta', 'text': block['text']}})
                    event('content_block_stop', {'type': 'content_block_stop', 'index': index})
                event('message_delta', {'type': 'message_delta', 'delta': {'stop_reason': reason, 'stop_sequence': None}, 'usage': {'output_tokens': 10}})
                event('message_stop', {'type': 'message_stop'})
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        retained = {k:v for k,v in os.environ.items() if k.upper() in {'PATH','HOME','USERPROFILE','SYSTEMROOT','WINDIR','COMSPEC','PATHEXT','TEMP','TMP','TMPDIR','LANG','LC_ALL','TERM','NUMBER_OF_PROCESSORS','PROGRAMFILES','PROGRAMFILES(X86)','LOCALAPPDATA','APPDATA','USER','USERNAME','LOGNAME','SHELL'}}
        env = dict(retained, ANTHROPIC_API_KEY='synthetic-local-fixture-token', ANTHROPIC_BASE_URL='http://127.0.0.1:' + str(server.server_port), CLAUDE_CONFIG_DIR=str(config), CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1', DISABLE_TELEMETRY='1', DISABLE_ERROR_REPORTING='1', CLAUDE_CODE_DISABLE_AUTOUPDATER='1')
        env.pop('ANTHROPIC_AUTH_TOKEN', None)
        try:
            for index, (name, target) in enumerate(targets):
                phase[0] = index
                result = subprocess.run([str(sentinel), 'guard', '--project', str(project), '--', str(claude), '--print', '--output-format', 'json', '--max-turns', '4'], input='Run only the synthetic requested fixture.', capture_output=True, text=True, env=env, timeout=90)
                if result.returncode:
                    raise AssertionError('Guard/provider failed (' + name + '): ' + result.stderr[-2000:] + result.stdout[-1000:])
                if name in ('allowed', 'approved'):
                    assert target.is_file(), 'Real client did not execute the permitted Write tool'
                else:
                    assert target.read_bytes() == original_policy, 'Real client changed the protected policy'
            assert offered == {'allowed', 'denied', 'approved'}, 'The actual tool requests were not offered'
            decisions = [json.loads(line) for line in (project / '.sentinel' / 'agent' / 'decisions.jsonl').read_text().splitlines()]
            assert any(d['decision'] == 'allow' for d in decisions)
            assert any(d['decision'] == 'deny' for d in decisions)
            assert any(d['code'] == 'AGENT_APPROVAL_CONSUMED' for d in decisions)
            assert 'SYNTHETIC FIXTURE ONLY' not in json.dumps(decisions)
            print('Claude ' + VERSION + ': real-client permitted edit and protected-edit denial and exact-action approval passed against localhost API')
        finally:
            server.shutdown()
            thread.join(timeout=5)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sentinel', required=True, type=Path)
    parser.add_argument('--claude', type=Path)
    parser.add_argument('--install-client', action='store_true')
    args = parser.parse_args()
    sentinel = args.sentinel.resolve()
    if args.claude:
        run_fixture(sentinel, args.claude.resolve())
    elif args.install_client:
        with tempfile.TemporaryDirectory(prefix='sentinel-claude-client-') as folder:
            npm = Path(shutil.which('npm.cmd' if os.name == 'nt' else 'npm')).resolve()
            cli = npm.parent / 'node_modules' / 'npm' / 'bin' / 'npm-cli.js' if os.name == 'nt' else npm
            subprocess.run([shutil.which('node'), str(cli), 'install', '--prefix', folder, '--registry=https://registry.npmjs.org/', '--strict-ssl=true', '--ignore-scripts', '--no-audit', '--no-fund', '@anthropic-ai/claude-code@' + VERSION], check=True)
            host = {'Darwin': 'darwin', 'Windows': 'win32', 'Linux': 'linux'}[platform.system()]
            arch = 'arm64' if platform.machine().lower() in ('arm64', 'aarch64') else 'x64'
            binary = Path(folder) / 'node_modules' / '@anthropic-ai' / ('claude-code-' + host + '-' + arch) / ('claude.exe' if os.name == 'nt' else 'claude')
            run_fixture(sentinel, binary)
    else:
        parser.error('Provide --claude or --install-client')

if __name__ == '__main__':
    main()
