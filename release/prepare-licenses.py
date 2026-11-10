#!/usr/bin/env python3
"""Collect notices and exact module sources from release binary build information.

No packages are installed or executed. Sources are hash-checked against Go's
embedded h1 checksums. Downloads are cached outside the public source tree.
"""
import argparse, base64, concurrent.futures, hashlib, io, json, os, pathlib, re
import subprocess, tarfile, urllib.parse, urllib.request, zipfile, shutil

ROOT = pathlib.Path(__file__).resolve().parent.parent

def sha(data):
    return hashlib.sha256(data).hexdigest()

def members(deb):
    data = deb.read_bytes()
    if data[:8] != b'!<arch>\n':
        raise ValueError(f'not a Debian archive: {deb.name}')
    offset = 8
    while offset < len(data):
        header = data[offset:offset+60]
        size = int(header[48:58])
        name = header[:16].decode().strip().rstrip('/')
        yield name, data[offset+60:offset+60+size]
        offset += 60 + size + size % 2

def escaped(value):
    return ''.join('!'+c.lower() if c.isupper() else c for c in value)

def download(url, target):
    if not target.exists():
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_suffix(target.suffix+'.tmp')
        temp.write_bytes(data)
        temp.replace(target)
    return target.read_bytes()

def ziphash(z):
    digest = hashlib.sha256()
    for name in sorted(n for n in z.namelist() if not n.endswith('/')):
        if '\n' in name:
            raise ValueError('invalid module filename')
        digest.update((sha(z.read(name))+'  '+name+'\n').encode())
    return 'h1:'+base64.b64encode(digest.digest()).decode()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dist', required=True, type=pathlib.Path)
    parser.add_argument('--go', default='go')
    parser.add_argument('--cache', required=True, type=pathlib.Path)
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    modules, binaries, tools = {}, [], set()
    env = dict(os.environ, GOTOOLCHAIN='local')
    for deb in sorted(args.dist.glob('*.deb')):
        for name, data in members(deb):
            if not name.startswith('data.tar'):
                continue
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                for member in archive:
                    if not member.isfile() or not (member.name.startswith('./usr/bin/') or member.name == './usr/lib/ara/sing-box'):
                        continue
                    payload = archive.extractfile(member).read()
                    if payload[:4] != b'\x7fELF':
                        continue
                    binary = args.cache/'inspect-binary'
                    binary.write_bytes(payload)
                    info = subprocess.check_output([args.go, 'version', '-m', str(binary)], env=env, text=True)
                    lines = info.splitlines()
                    tool = lines[0].rsplit(': ', 1)[-1]
                    tools.add(tool)
                    label = deb.name+':'+member.name.removeprefix('./')
                    binaries.append({'binary':label, 'sha256':sha(payload), 'toolchain':tool, 'build_information': '\n'.join(lines[1:])+'\n'})
                    for line in lines[1:]:
                        fields = line.split()
                        if fields and fields[0] == '=>':
                            raise ValueError('replacement requires explicit review')
                        if len(fields) < 3 or fields[0] not in ('dep', 'mod') or fields[2] == '(devel)':
                            continue
                        key = (fields[1], fields[2])
                        expected = fields[3] if len(fields)>3 else ''
                        item = modules.setdefault(key, {'module':key[0], 'version':key[1], 'h1':expected, 'binaries':[]})
                        if item['h1'] != expected:
                            raise ValueError('inconsistent module checksum')
                        item['binaries'].append(label)
    if not binaries or not any(p == 'github.com/sagernet/sing-box' for p, v in modules):
        raise ValueError('release must include ARA and the pinned transport engine')
    def collect(item):
        path, version = item['module'], item['version']
        stem = escaped(path)+'/@v/'+escaped(version)
        url = 'https://proxy.golang.org/'+stem+'.zip'
        cached = args.cache/'modules'/(stem+'.zip')
        data = download(url, cached)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            calculated = ziphash(z)
            if item['h1'] and calculated != item['h1']:
                raise ValueError('module source checksum mismatch: '+path)
            notices = []
            prefix = path+'@'+version+'/'
            for name in z.namelist():
                relative = name[len(prefix):] if name.startswith(prefix) else ''
                if not relative or name.endswith('/'):
                    continue
                base = pathlib.PurePosixPath(relative).name
                if re.match(r'^(licen[cs]e|copying|notice|copyright|patents)([._-].*)?$', base, re.I):
                    destination = ROOT/'licenses/third-party'/path/version/relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(z.read(name))
                    notices.append(str(destination.relative_to(ROOT)))
        return dict(item, source_url=url, source_zip_sha256=sha(data), verified_h1=calculated,
                    source_archive='modules/'+stem+'.zip', notice_files=sorted(notices))
    records = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(collect, item):key for key, item in sorted(modules.items())}
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                records.append(future.result())
            except Exception as exc:
                print('FAILED', key, str(exc), flush=True)
                raise
            print(f'Collected {len(records)}/{len(modules)}: {key[0]}', flush=True)
    records.sort(key=lambda x:(x['module'], x['version']))
    # Toolchain sources include standard-library licenses and vendored notices.
    tool_records = []
    for version in sorted(tools):
        url = f'https://go.dev/dl/{version}.src.tar.gz'
        target = args.cache/'toolchains'/(version+'.src.tar.gz')
        data = download(url, target)
        hashes = json.loads(download('https://go.dev/dl/?mode=json&include=all', args.cache/'go-releases.json'))
        expected = next((f['sha256'] for r in hashes for f in r['files'] if f['filename'] == target.name), None)
        if not expected or sha(data) != expected:
            raise ValueError('toolchain source not verified: '+version)
        notice_files = []
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            for member in archive:
                if member.isfile() and re.match(r'^(LICENSE|PATENTS|NOTICE|COPYING)([._-].*)?$', pathlib.PurePosixPath(member.name).name, re.I):
                    dest = ROOT/'licenses/third-party/go'/version/member.name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(archive.extractfile(member).read())
                    notice_files.append(str(dest.relative_to(ROOT)))
        tool_records.append({'version':version, 'source_url':url, 'sha256':expected, 'source_archive':'toolchains/'+target.name, 'notice_files':notice_files})
    # Native code embedded in a Go module needs its own corresponding source.
    native = json.loads((ROOT/'licenses/NATIVE-SOURCES.json').read_text())
    for record in native['sources']:
        for module, version in record['required_modules'].items():
            if (module, version) not in modules:
                raise ValueError('native source lock requires review: '+module)
        target = args.cache/'native'/record['archive']
        data = download(record['source_url'], target)
        if sha(data) != record['sha256']:
            raise ValueError('native source checksum mismatch')
        shutil.copyfile(target, args.dist/record['archive'])
    inventory = {'format':1, 'ara_license':'AGPL-3.0-or-later', 'method':'union of embedded Go build information in all release Debian binaries; h1 verified module source archives', 'binaries':binaries, 'modules':records, 'toolchains':tool_records}
    destination = ROOT/'licenses/INVENTORY.json'
    destination.write_text(json.dumps(inventory, indent=2, ensure_ascii=False)+'\n')
    with tarfile.open(args.dist/'THIRD-PARTY-SOURCES.tar.gz', 'w:gz') as archive:
        for record in records:
            archive.add(args.cache/record['source_archive'], arcname=record['source_archive'])
        for record in tool_records:
            archive.add(args.cache/record['source_archive'], arcname=record['source_archive'])
        archive.add(destination, arcname='INVENTORY.json')
    missing = [x['module']+'@'+x['version'] for x in records if not x['notice_files']]
    print(json.dumps({'binaries':len(binaries), 'modules':len(records), 'toolchains':len(tools), 'missing_notice_files':missing}, indent=2))
    # Modules without notices must be resolved explicitly; never label them MIT by default.
    (args.cache/'missing-notices.json').write_text(json.dumps(missing, indent=2)+'\n')

if __name__ == '__main__':
    main()
