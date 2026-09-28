"""Exact-value string sharing and streamed hashing for the unchanged miner."""
import ast
import hashlib
import inspect
import json


def install(miner):
    original_record=miner._record_file
    original_fingerprint=miner._file_fingerprint
    source=inspect.getsource(original_fingerprint)
    if 'hashlib.sha256(json.dumps(payload, ensure_ascii=False).encode()).hexdigest()' not in source:
        raise RuntimeError('Fingerprint serialization changed; revalidate storage adapter')
    fields=None
    for node in ast.walk(ast.parse(source)):
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='fields' for t in node.targets):
            fields=ast.literal_eval(node.value)
    if not isinstance(fields,tuple):raise RuntimeError('Fingerprint fields could not be verified')
    pool={};stats={'duplicate_string_values_shared':0,'shared_string_characters':0}
    def share(value):
        if isinstance(value,str):
            prior=pool.setdefault(value,value)
            if prior is not value:
                stats['duplicate_string_values_shared']+=1
                stats['shared_string_characters']+=len(value)
            return prior
        if isinstance(value,dict):return {key:share(item) for key,item in value.items()}
        if isinstance(value,list):return [share(item) for item in value]
        return value
    def record(*args,**kwargs):return share(original_record(*args,**kwargs))
    def fingerprint(files):
        payload=sorted(json.dumps({key:row.get(key) for key in fields},sort_keys=True,ensure_ascii=False) for row in files)
        digest=hashlib.sha256()
        for chunk in json.JSONEncoder(ensure_ascii=False).iterencode(payload):digest.update(chunk.encode())
        return digest.hexdigest()
    miner._record_file=record;miner._file_fingerprint=fingerprint
    def finish():
        miner._record_file=original_record;miner._file_fingerprint=original_fingerprint
        result=dict(stats,unique_string_values=len(pool),adapter='exact_string_sharing_and_streamed_fingerprint',selection_changed=False)
        pool.clear()
        return result
    return finish
