"""Robot keywords that submit and verify fresh existing-queue transactions."""
from pathlib import Path
import os
import sys
sys.path.insert(0,str(Path(__file__).parent))
from robot_client import Engine

class OPEMOSRobot:
    ROBOT_LIBRARY_SCOPE='SUITE'
    ROBOT_AUTO_KEYWORDS=False
    def __init__(self):
        self.engine=None
    def _engine(self):
        if self.engine is None:
            self.engine=Engine(os.environ['OPEMOS_ROBOT_PRIVATE_RESULTS'])
        return self.engine
    def get_keyword_names(self):
        return ['Execute Exact VM','Execute Every Platform Artifact','Prove Scoped Ubuntu Connection','Retain Independent Outcomes','Execute Exact Produced Platform']
    def run_keyword(self,name,args,kwargs=None):
        if name=='Prove Scoped Ubuntu Connection':
            return self._execute(lambda _: self._engine().connection(), 'connection-only-old-artifact')
        if name=='Execute Exact Produced Platform':return self._execute(lambda _:self._engine().produced_platform(),'exact-produced-platform')
        if name=='Execute Exact VM':return self._execute(self._engine().vm,args[0])
        if name=='Execute Every Platform Artifact':return self._execute(self._engine().platform,args[0])
        if name=='Retain Independent Outcomes':
            if self.engine is not None:
                self.engine.persist();self._summary()

    def _execute(self,function,subject):
        try:
            result=function(subject)
            from robot.api import logger
            import html
            for item in (result or {}).get('exports',[]):
                if item['kind']=='screenshot':
                    name=html.escape(Path(item['path']).name,quote=True)
                    logger.info('<a href="'+name+'">Actual current-run screenshot</a>',html=True)
            return result
        except Exception as error:
            # GitHub annotations are emitted only from this exact executing
            # Robot keyword's verified deviation, never an old manual result.
            message=(str(subject)+': '+type(error).__name__+': '+str(error))[:1000]
            message=message.replace('%','%25').replace('\r','%0D').replace('\n','%0A')
            print('::error title=OPEMOS Robot deviation::'+message)
            raise
    def _summary(self):
        name=os.environ.get('GITHUB_STEP_SUMMARY')
        if not name:return
        with open(name,'a')as out:
            out.write('| Exact VM | Actual Robot outcome |\n|---|---|\n')
            for key,row in self.engine.results.items():
                out.write('| '+key.replace('|','/')+' | '+row['status']+' |\n')
            out.write('\n| Platform executable outputs | Actual outcome |\n|---|---|\n')
            for key,row in self.engine.artifacts.items():out.write('| '+key+' | '+row['status']+' |\n')
            out.write('\nRobot reports, current screenshots, argv, raw logs and NVIDIA evidence are in this run artifact. Missing/failed evidence never becomes a skipped pass.\n')
