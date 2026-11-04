// Every fixture server must use the same reviewed workspace interpreter.
const fs=require('node:fs'),path=require('node:path');
const repositoryRoot=path.resolve(__dirname,'../../../..');
const workspacePython=path.join(repositoryRoot,'.venv',process.platform==='win32'?'Scripts/python.exe':'bin/python');
module.exports=process.env.LIGHTWORK_BROWSER_PYTHON||(fs.existsSync(workspacePython)?workspacePython:(process.platform==='win32'?'python':'python3'));
