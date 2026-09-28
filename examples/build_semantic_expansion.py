"""Create fresh multi-language/schema/flow history; never execute fixture code."""
import json
from pathlib import Path
import sys

PROJECT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT/'tests'))
from synthetic_histories import HEADER,commit,init,git

output=Path(sys.argv[1]).resolve()
if output.exists():raise SystemExit('Choose a new fixture directory; existing data is preserved.')
output.mkdir(parents=True);repo=output/'repo';init(repo)
source=HEADER+'''from jsonschema import validate
from pydantic import EmailStr,Field
from helper import relay,mask
class Account:
    value: str = Field(json_schema_extra={"format":"email"})
def schema_use(payload):
    validate(payload,{"$ref":"schema.json#/$defs/record"})
    logger.info("value",payload["value"])
def typed_model(data:Account):
    logger.info("value",data.value)
async def contact(data:EmailStr):
    payload={"v":await relay(data)}
    key="v"
    logger.info("value",payload[key])
def flag(data):
    value=True
    logger.info("value",value)
def opaque(NHI):
    logger.info("value",NHI)
def documented(data):
    """:param data: Opaque shipment scheduling reference."""
    logger.info("value",data)
def redacted(data):
    logger.info("value",mask(data))
'''
schema={'$defs':{'record':{'type':'object','properties':{'value':{'type':'string','format':'email'}}}}}
files={'app.py':source,'schema.json':json.dumps(schema),
       'helper.py':'from second import identity\nasync def relay(value):\n    return identity(value)\ndef mask(value):\n    return value\n',
       'second.py':'def identity(value):\n    return value\n',
       'app.ts':'type Receipt = string;\ninterface Account { value: Receipt; active: boolean; }\nfunction emit(data: Account) { const value=data.value; console.log("v",value); }\n',
       'app.js':'function emit(data) { const value=true; console.log("v",value); }\nfunction other(value) { console.log("v",value); }\n',
       'app.go':'package main\nimport "log"\ntype Receipt string\ntype Account struct { Value Receipt; Active bool }\nfunc emit(data Account) { value := data.Value; log.Printf("%v",value) }\n',
       'App.java':'class App {\n void other() { boolean value=true; }\n void emit(Object data) { boolean value=false; logger.info("FIXTURE", value, data); }\n void opaque(Object NHI) { logger.info("FIXTURE", NHI); }\n}\n'}
initial=commit(repo,files,'synthetic schema and multi-language introduction')
commit(repo,{'helper.py':files['helper.py'].replace('def mask(value):\n    return value','def mask(value):\n    return "FIXTURE_MASK"'),
             'schema.json':json.dumps({'$defs':{'record':{'properties':{'value':{'description':'Opaque shipping reference','type':'string'}}}}})},
       'synthetic cross-file mask and schema change',actor='human',day=3)
git(repo,'mv','app.py','renamed.py');commit(repo,{},'synthetic rename',actor='unknown',day=4)
tip=commit(repo,{'renamed.py':HEADER+'def emit(data):\n    pass\n'},'synthetic deleted logs',actor='agent',day=5)
row={'is_synthetic':True,'fixture_repository_id':'semantic-expansion-fixture','local_repo_path':str(repo),
     'initial_commit_shas':[initial],'target_ref':tip,
     'synthetic_author_mapping':{'agent@example.invalid':'agent','human@example.invalid':'human_led'}}
(output/'input.jsonl').write_text(json.dumps(row)+'\n')
print(json.dumps({'initial_sha':initial,'tip_sha':tip,'commits':4,'target_code_executed':False}))
