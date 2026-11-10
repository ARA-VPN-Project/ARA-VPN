#!/usr/bin/env python3
"""Verify licensing payload and source archive checksums without installation."""
import argparse, hashlib, importlib.util, io, json, pathlib, tarfile, sys
sys.dont_write_bytecode=True
ROOT=pathlib.Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('prepare_licenses',ROOT/'release/prepare-licenses.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dist',type=pathlib.Path,required=True);a=p.parse_args()
 inventory=json.loads((ROOT/'licenses/INVENTORY.json').read_text());native=json.loads((ROOT/'licenses/NATIVE-SOURCES.json').read_text())
 assert inventory['ara_license']=='AGPL-3.0-or-later'
 assert (ROOT/'LICENSE').read_text().startswith('                    GNU AFFERO GENERAL PUBLIC LICENSE')
 binary_hashes={b['binary']:b['sha256'] for b in inventory['binaries']}
 notices={f for m in inventory['modules'] for f in m['notice_files']}
 notices.update(f for m in inventory['toolchains'] for f in m['notice_files'])
 notices.update(f for m in native['sources'] for f in m['notice_files'])
 assert all(m['notice_files'] for m in inventory['modules']), 'unresolved module notice'
 files={'LICENSE','NOTICE','TRADEMARKS.md','SOURCES.md','licenses/GPL-3.0.txt','licenses/SING-BOX-LICENSE','licenses/INVENTORY.json','licenses/NATIVE-SOURCES.json'}|notices
 for path in files:assert (ROOT/path).is_file(),path
 verified_binaries=[];packages=[]
 for deb in sorted(a.dist.glob('*.deb')):
  package=deb.name.split('_')[0];seen=set()
  for name,data in helper.members(deb):
   if not name.startswith('data.tar'):continue
   with tarfile.open(fileobj=io.BytesIO(data)) as t:
    for m in t:
     if not m.isfile():continue
     path=m.name.removeprefix('./');label=deb.name+':'+path
     if label in binary_hashes:
      assert sha(t.extractfile(m).read())==binary_hashes[label], 'binary changed: '+label
      verified_binaries.append(label)
     prefix='usr/share/doc/'+package+'/'
     if path.startswith(prefix):
      relative=path[len(prefix):]
      if relative in files:
       assert t.extractfile(m).read()==(ROOT/relative).read_bytes(),deb.name+':'+relative
       seen.add(relative)
  assert files<=seen, str((deb.name,sorted(files-seen)))
  packages.append(deb.name)
 assert sorted(verified_binaries)==sorted(binary_hashes), 'incomplete release binary inventory'
 expected={m['source_archive']:m['source_zip_sha256'] for m in inventory['modules']}
 expected.update({m['source_archive']:m['sha256'] for m in inventory['toolchains']})
 seen=set()
 with tarfile.open(a.dist/'THIRD-PARTY-SOURCES.tar.gz','r|gz') as t:
  for m in t:
   if m.name in expected:
    assert sha(t.extractfile(m).read())==expected[m.name], 'source corruption: '+m.name
    seen.add(m.name)
   elif m.name=='INVENTORY.json':
    assert json.loads(t.extractfile(m).read())==inventory, 'source inventory mismatch'
 assert seen==set(expected),'missing exact source archives'
 for m in native['sources']:
  assert sha((a.dist/m['archive']).read_bytes())==m['sha256'],m['archive']
 result={'status':'PASS','license':'AGPL-3.0-or-later','packages_verified':len(packages),'binary_payloads_unchanged':len(verified_binaries),'module_versions':len(inventory['modules']),'toolchain_sources':len(inventory['toolchains']),'notice_files':len(notices),'native_source_archives':len(native['sources']),'exact_source_archives_verified':len(seen)}
 print(json.dumps(result,indent=2))
if __name__=='__main__':main()
