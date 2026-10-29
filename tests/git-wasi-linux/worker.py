#!/usr/bin/env python3
"""Synthetic fixture process owner, invoked only inside the disposable Linux VM."""
import base64
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

CAPTURE = 131072


def kill_owned(child):
    # The unreaped direct child anchors this process-group identity. Linux may
    # report ESRCH if no process remains; no PID or foreign group is adopted.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run(argv, cwd, timeout, environment, minimum_free=0):
    child = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    selector = selectors.DefaultSelector()
    chunks = [bytearray(), bytearray()]
    started = time.monotonic()
    try:
        for number, pipe in enumerate((child.stdout, child.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, number)
        deadline = started + timeout
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise TimeoutError('owned process deadline')
            space = os.statvfs(cwd)
            if space.f_bavail * space.f_frsize < minimum_free:
                raise RuntimeError('private build disk reserve')
            for key, _ in selector.select(0.05):
                data = os.read(key.fd, 4096)
                if not data:
                    selector.unregister(key.fileobj)
                else:
                    if len(chunks[key.data]) + len(data) > CAPTURE:
                        raise RuntimeError('owned process capture bound')
                    chunks[key.data].extend(data)
        while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
            if time.monotonic() >= deadline:
                raise TimeoutError('owned process deadline after EOF')
            time.sleep(0.005)
        kill_owned(child)
        code = child.wait(timeout=2)
        return {'completionKnown': True, 'exitCode': code,
                'durationMilliseconds': round((time.monotonic() - started) * 1000),
                'stdoutBase64': base64.b64encode(chunks[0]).decode(),
                'stderrBase64': base64.b64encode(chunks[1]).decode()}
    finally:
        if child.returncode is None:
            kill_owned(child)
            child.wait(timeout=2)
        selector.close()
        child.stdout.close()
        child.stderr.close()


def main():
    try:
        request = json.loads(Path(sys.argv[1]).read_text())
        environment = dict(os.environ) if request['kind'] == 'build' else {}
        environment.update(request.get('environment', {}))
        result = run(request['argv'], request['cwd'], request['timeoutSeconds'],
                     environment, request.get('minimumFreeBytes', 0))
        print(json.dumps(result))
        return 0
    except BaseException as error:
        print(json.dumps({'completionKnown': False, 'errorClass': type(error).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
