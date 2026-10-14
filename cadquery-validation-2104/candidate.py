import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request
import zipfile
import xml.etree.ElementTree as ET

PR_HEAD='5dfbf5c89932d9c438ba449e29732a6a56680aae'; MASTER_HEAD='5f5bc62b255f62e3512105740025361b6c31eddd'
MERGE_HEAD='2b85056876c75d4380cf821aa4055d44963cccf7'; MERGE_TREE='ffd928a746b4cfaf8a2a27a3b8c7e4111efb05f1'
SOURCE_HASH='c940a32d7e7009cc5793067c76783969571513087d6c9362cb7fa9c2c36cc29c6'; BASE_SOURCE_HASH='054b005f9a3a936e9c47455493a4078bc33fc2c342f69f9d0fa5c6f7ec0689c6'
RUN_ID='38646497682'; PAYLOAD_SHA='35e62aa69468ceea850e3b60a41f38260bb719c3'; ARTIFACT_ID='11933066912'; ARTIFACT_NAME='cadquery-baseline-linux-2107'; MANIFEST_SHA='df82892c75a36fd53e223957766ef3dbaecbea46fa8baded7c3d0cf8ca74cbed'
ROOT=Path.cwd().resolve(); TEMP=Path(os.environ['RUNNER_TEMP']).resolve()/'cadquery-candidate'; ARTIFACTS=TEMP/'artifacts'; MAMBA=TEMP/'miniforge/bin/mamba'; CONDA=TEMP/'miniforge/bin/conda'; ENV=TEMP/'environment'


def run(args, env=None, cwd=ROOT):
    print('COMMAND',json.dumps([str(x) for x in args]),flush=True)
    return subprocess.run([str(x) for x in args],env=env,cwd=cwd,check=True)

def capture(name,args,env):
    out,err=ARTIFACTS/f'{name}.stdout',ARTIFACTS/f'{name}.stderr'
    if out.exists() or err.exists(): raise FileExistsError(name)
    with out.open('x') as so,err.open('x') as se: p=subprocess.run([str(x) for x in args],cwd=ROOT,env=env,stdout=so,stderr=se)
    (ARTIFACTS/f'{name}.exit').write_text(f'{p.returncode}\n'); return p.returncode

def tree_digest():
    h=hashlib.sha256(); paths=subprocess.check_output(['git','ls-files','-z']).split(b'\0')[:-1]
    for raw in paths:h.update(raw+b'\0'+(ROOT/raw.decode()).read_bytes()+b'\0')
    return len(paths),h.hexdigest()

def identity(stage):
    assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==MERGE_HEAD
    assert subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip()==MERGE_TREE
    assert not subprocess.check_output(['git','diff','--name-only']) and not subprocess.check_output(['git','diff','--cached','--name-only'])
    n,d=tree_digest(); assert n==219 and d==SOURCE_HASH
    (ARTIFACTS/f'source-identity-{stage}.json').write_text(json.dumps({'stage':stage,'head':MERGE_HEAD,'tree':MERGE_TREE,'tracked_files':n,'tracked_digest':d},indent=2)+'\n')

def safe_extract(z,dest):
    seen=set()
    for i in z.infolist():
        p=Path(i.filename)
        if p.is_absolute() or '..' in p.parts or i.filename in seen or i.is_dir(): raise ValueError('unsafe artifact path')
        seen.add(i.filename)
        if i.external_attr>>16 & 0o170000 == 0o120000: raise ValueError('artifact link')
    z.extractall(dest)

def artifact():
    token=os.environ.pop('GITHUB_TOKEN',None); assert token
    req=urllib.request.Request(f'https://api.github.com/repos/RanaPriyansh/arrow-rs-object-store/actions/runs/{RUN_ID}/artifacts',headers={'Authorization':f'Bearer {token}','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(req,timeout=30) as r: meta=json.loads(r.read())
    hit=[a for a in meta['artifacts'] if str(a['id'])==ARTIFACT_ID and a['name']==ARTIFACT_NAME and not a['expired']]
    assert len(hit)==1 and hit[0]['workflow_run']['id']==int(RUN_ID)
    u=hit[0]['archive_download_url']; r=urllib.request.Request(u,headers={'Accept':'application/vnd.github+json'})
    archive=TEMP/'baseline.zip'
    with urllib.request.urlopen(r,timeout=120) as src,archive.open('wb') as dst: shutil.copyfileobj(src,dst)
    dest=TEMP/'baseline'; dest.mkdir()
    with zipfile.ZipFile(archive) as z: safe_extract(z,dest)
    raw=(dest/'artifact-manifest.json').read_bytes(); assert hashlib.sha256(raw).hexdigest()==MANIFEST_SHA
    m=json.loads(raw); assert len(m)==57
    for name,digest in m.items(): assert hashlib.sha256((dest/name).read_bytes()).hexdigest()==digest
    (ARTIFACTS/'baseline-binding.json').write_text(json.dumps({'run':RUN_ID,'payload':PAYLOAD_SHA,'artifact':ARTIFACT_ID,'name':ARTIFACT_NAME,'manifest_sha256':MANIFEST_SHA},indent=2)+'\n')
    return dest

def check_baseline(b):
    assert json.loads((b/'source-identity-initial.json').read_text())['tracked_digest']==BASE_SOURCE_HASH
    assert json.loads((b/'source-identity-final.json').read_text())['tracked_digest']==BASE_SOURCE_HASH
    ids=json.loads((b/'run-identities.json').read_text()); assert ids['payload_sha']==PAYLOAD_SHA and ids['conda_python']=='Python 3.12.15'
    for x in ['environment-solve','black','mypy','pytest','pip-wheel-build','export-conda-explicit','export-conda-list','export-environment-resolved','export-pip-freeze','export-pip-inspect']:
        assert (b/f'{x}.exit').read_text().strip()=='0'
    root=ET.parse(b/'pytest.xml').getroot().find('testsuite'); assert root.attrib=={**root.attrib,'tests':'901','failures':'0','errors':'0','skipped':'3'}
    req=(b/'pip-only-hashed-requirements.txt').read_text(); assert req.count('--hash=sha256:')==7 and len(list((b/'wheels').glob('*.whl')))==7
    assert (b/'environment.yml').read_bytes()==(b/'environment.yml').read_bytes()

def merge():
    assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==PR_HEAD
    run(['git','fetch','--no-tags','--depth=4','https://github.com/CadQuery/cadquery.git',PR_HEAD,MASTER_HEAD])
    assert subprocess.check_output(['git','merge-base',PR_HEAD,MASTER_HEAD],text=True).strip()=='9a6a705fe73ae94300974a3c668719f907b6353f'
    run(['git','-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false','merge','--no-ff','--no-commit','--strategy=ort',MASTER_HEAD])
    assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==PR_HEAD
    assert subprocess.check_output(['git','rev-parse','MERGE_HEAD'],text=True).strip()==MASTER_HEAD
    msg=Path(__file__).with_name('merge-message.txt'); assert msg.read_bytes()==Path(__file__).with_name('merge-message.txt').read_bytes()
    e=os.environ.copy(); e.update({'GIT_AUTHOR_NAME':'RanaPriyansh','GIT_AUTHOR_EMAIL':'priyanshrana18@gmail.com','GIT_AUTHOR_DATE':'@1792016770 +0530','GIT_COMMITTER_NAME':'RanaPriyansh','GIT_COMMITTER_EMAIL':'priyanshrana18@gmail.com','GIT_COMMITTER_DATE':'@1792016770 +0530'})
    run(['git','-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false','-c','i18n.commitEncoding=UTF-8','commit','--no-verify','--cleanup=verbatim','--file',msg],env=e)
    assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==MERGE_HEAD
    assert subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip()==MERGE_TREE
    assert (ARTIFACTS/'merge-commit.raw').write_bytes(subprocess.check_output(['git','cat-file','commit','HEAD'])) is None

def main():
    TEMP.mkdir(parents=True,exist_ok=True); ARTIFACTS.mkdir(parents=True,exist_ok=True)
    env=os.environ.copy(); env.pop('GITHUB_TOKEN',None); env.update({'MAMBA_ROOT_PREFIX':str(TEMP/'mamba-root'),'CONDA_PKGS_DIRS':str(TEMP/'conda-pkgs'),'NUMBA_JIT_COVERAGE':'1','NUMBA_DISABLE_JIT':'1','OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1','MKL_NUM_THREADS':'1','NUMBA_NUM_THREADS':'1'})
    b=artifact(); check_baseline(b); merge(); identity('merged')
    assert capture('conda-create',[MAMBA,'create','--yes','--prefix',ENV,'--file',b/'export-conda-explicit.stdout'],env)==0
    assert capture('pip-replay',[MAMBA,'run','--prefix',ENV,'python','-m','pip','install','--no-index','--find-links',b/'wheels','--no-deps','--require-hashes','--requirement',b/'pip-only-hashed-requirements.txt'],env)==0
    for n,a in [('conda-before',[CONDA,'list','--prefix',ENV,'--json']),('pip-before',[MAMBA,'run','--prefix',ENV,'python','-m','pip','inspect'])]: assert capture(n,a,env)==0
    assert capture('candidate-editable',[MAMBA,'run','--prefix',ENV,'python','-m','pip','install','--no-index','--no-deps','--no-build-isolation','--editable','.'],env)==0
    failures=[capture(n,a,env) for n,a in [('black',[MAMBA,'run','--prefix',ENV,'black','.','--diff','--check']),('mypy',[MAMBA,'run','--prefix',ENV,'mypy','cadquery']),('pytest',[MAMBA,'run','--prefix',ENV,'pytest','-v','--gui','--cov','--junitxml',ARTIFACTS/'pytest.xml'])]]
    for n,a in [('conda-after',[CONDA,'list','--prefix',ENV,'--json']),('pip-after',[MAMBA,'run','--prefix',ENV,'python','-m','pip','inspect'])]: assert capture(n,a,env)==0
    if any(failures): raise SystemExit(1)

if __name__=='__main__': main()
