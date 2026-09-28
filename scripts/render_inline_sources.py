"""Render through Windows or POSIX Node, then emit a host-executor-native reference.

This wrapper is the project entry point. It never overwrites an existing fragment,
never modifies the installed plugin, and validates the returned path boundary.
"""
import argparse,json,os,re,subprocess
from pathlib import Path
from prepare_inline_visualization import executor_path,prepare

def child_path(path,windows):
 raw=str(path)
 if not (raw.startswith('/') or re.match(r'^[A-Za-z]:[\\/]',raw)):raw=str(Path(raw).resolve())
 value=str(Path(executor_path(raw)).resolve())
 if windows:
  match=re.fullmatch(r'/mnt/([a-z])/(.*)',value)
  if match:return match[1].upper()+':/'+match[2]
  if os.name!='nt':raise ValueError('Windows renderer requires a Windows-mounted input/output path')
 return value

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ['node','renderer','input','output','allowed-root']:p.add_argument('--'+name,required=True)
 p.add_argument('--receipt');a=p.parse_args();out=Path(executor_path(a.output)).resolve();root=Path(executor_path(a.allowed_root)).resolve(strict=True)
 if not out.is_relative_to(root):raise ValueError('Output outside explicitly allowed root')
 if out.exists():raise FileExistsError('Existing fragment is immutable; choose a new output name')
 if a.receipt and Path(a.receipt).exists():raise FileExistsError('Receipt exists')
 node=executor_path(a.node);windows=node.lower().endswith('.exe')
 run=subprocess.run([node,child_path(a.renderer,windows),'--input',child_path(a.input,windows),'--output',child_path(out,windows)],check=True,capture_output=True,text=True,encoding='utf-8')
 result=json.loads(run.stdout.strip().splitlines()[-1]);receipt=prepare(result['path'],str(root))
 assert Path(receipt['path']).resolve()==out,'Renderer returned unexpected file'
 receipt['renderer_result']=result
 if a.receipt:
  with Path(a.receipt).open('x',encoding='utf-8') as f:f.write(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps(receipt,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
