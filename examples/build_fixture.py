"""Create synthetic commits only; never execute the application in the fixture."""
from pathlib import Path
import json
import os
import subprocess
import sys

project=Path(__file__).resolve().parents[1]
repo=project/'examples'/'fixture_repo'
if repo.exists():
    raise SystemExit('Fixture already exists; use its frozen examples/prs.example.jsonl')
repo.mkdir(mode=0o700)

def git(*args):
    return subprocess.run(['git','-C',str(repo),'-c','core.hooksPath=/dev/null',*args],capture_output=True,text=True,check=True).stdout.strip()

def commit(message,who,day):
    git('add','.')
    env={**os.environ,'GIT_AUTHOR_NAME':who,'GIT_AUTHOR_EMAIL':who+'@fixture.invalid','GIT_COMMITTER_NAME':who,'GIT_COMMITTER_EMAIL':who+'@fixture.invalid','GIT_AUTHOR_DATE':f'2026-01-{day:02}T12:00:00+00:00','GIT_COMMITTER_DATE':f'2026-01-{day:02}T12:00:00+00:00'}
    subprocess.run(['git','-C',str(repo),'-c','core.hooksPath=/dev/null','commit','-qm',message],env=env,check=True)
    return git('rev-parse','HEAD')

git('init','-b','main')
base='import logging\nfrom serializer import serialize_user\nlogger = logging.getLogger(__name__)\n\ndef login():\n    user = {"active": True, "password": "DUMMY_RESEARCH_SECRET_NOT_VALID"}\n    logger.info("login attempt")\n    logger.info("token count=%d", 7)\n'
(repo/'app.py').write_text(base)
(repo/'serializer.py').write_text('def serialize_user(user):\n    return dict(user)\n')
commit('Synthetic baseline','human',1)
intro=base.replace('logger.info("login attempt")','logger.info(\n        "login attempt: %s",\n        serialize_user(user),\n    )')
(repo/'app.py').write_text(intro)
c1=commit('Synthetic agent changes application log','agent',2)
(repo/'app.py').write_text(intro.replace('logger.info(\n','logger.debug(\n'))
commit('Synthetic level-only followup','human',3)
(repo/'serializer.py').write_text('def serialize_user(user):\n    return {"active": user["active"]}\n')
commit('Synthetic shared serializer allowlist','human',4)
git('mv','app.py','login.py');commit('Synthetic rename','unknown',5)
(repo/'login.py').write_text((repo/'login.py').read_text()+'\ndef unrelated():\n    return 3\n')
commit('Synthetic unrelated function','unknown',6)
row={'fixture_repository_id':'synthetic-basic-v1','is_synthetic':True,'local_repo_path':str(repo),'target_ref':'main','initial_commit_shas':[c1],'cohort':'calibration_only','pr_actor_type':'agent','synthetic_author_mapping':{'agent@fixture.invalid':'agent','human@fixture.invalid':'human_led','unknown@fixture.invalid':'unknown'}}
(project/'examples/prs.example.jsonl').write_text(json.dumps(row)+'\n')
(project/'examples/local_fixture_config.yaml').write_text('input:\n  prs_path: examples/prs.example.jsonl\n  offline: true\nmining:\n  max_history_commits_per_repository: 100\n')
print(json.dumps({'fixture_repository':str(repo),'initial_commit':c1,'target_tip':git('rev-parse','HEAD'),'is_synthetic':True}))
