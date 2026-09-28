"""Generate new synthetic Git data; never import/execute the target application."""
import json
from pathlib import Path
import sys

PROJECT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT/'tests'))
from synthetic_histories import HEADER, commit, init, git

output=Path(sys.argv[1]).resolve()
if output.exists():raise SystemExit('Choose a new fixture directory; existing data is preserved.')
output.mkdir(parents=True)
repo=output/'repo';init(repo)
source=HEADER+'''from pydantic import EmailStr
from helper import project
from typing import NewType
NHI=NewType("NHI",str)
def contact(data:EmailStr):
    value=data
    payload=project(value)
    logger.info(
        "data=%s",
        payload)
def flag(data):
    value=True
    logger.info("value=%s",value)
def business(NHI:NHI):
    logger.info("NHI=%s",NHI)
def unresolved(qx):
    logger.info("value=%s",qx)
'''
initial=commit(repo,{'app.py':source,'helper.py':'def project(value):\n    return {"contact":value,"active":True}\n'},'synthetic semantic introduction')
commit(repo,{'helper.py':'def project(value):\n    return {"active":True}\n'},'synthetic cross-file projection',actor='human',day=3)
git(repo,'mv','app.py','renamed.py');commit(repo,{},'synthetic rename',actor='unknown',day=4)
tip=commit(repo,{'renamed.py':HEADER+'def contact(data):\n    pass\n'},'synthetic deletion',actor='agent',day=5)
row={'is_synthetic':True,'fixture_repository_id':'semantic-calibration','local_repo_path':str(repo),
     'initial_commit_shas':[initial],'target_ref':tip,
     'synthetic_author_mapping':{'agent@example.invalid':'agent','human@example.invalid':'human_led'}}
(output/'input.jsonl').write_text(json.dumps(row)+'\n')
print(json.dumps({'fixture':str(output),'initial_sha':initial,'tip_sha':tip,'target_code_executed':False}))
