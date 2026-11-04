"""Pure option lifetime decision; no Root, device or VM acceptance claimed."""
import importlib.util
from pathlib import Path
import unittest

SPEC=importlib.util.spec_from_file_location('managed_vfio',Path(__file__).parents[1]/'scripts/omen_control/managed_vfio.py')
V=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(V)

class FirstInitializationTests(unittest.TestCase):
    def test_unloaded_driver_and_core_use_existing_first_initialization(self):
        self.assertEqual(V.initial_plan({'vfio_pci':False,'vfio_pci_core':False}),
            ['/var/lib/opemos-vfio-idle-d3/modprobe','--ignore-install','--first-time','vfio-pci','disable_idle_d3=1'])
    def test_loaded_or_unknown_option_lifetime_never_reloads(self):
        for state in ({'vfio_pci':True,'vfio_pci_core':True},
                      {'vfio_pci':False,'vfio_pci_core':True},
                      {'vfio_pci':True,'vfio_pci_core':False},
                      {'vfio_pci':0,'vfio_pci_core':False},{'vfio_pci':False},{}):
            with self.subTest(state=state),self.assertRaises(ValueError):V.initial_plan(state)

    def custody(self):
        before={'loaded':{'vfio_pci':False,'vfio_pci_core':False},'dependencies':{'vfio':True,'irqbypass':True}}
        result={'numeric':0,'closure':'KNOWN','EOF':True,'reaped':True,'primary':None,'secondary':[]}
        after={'option':'Y','modules':{n:{'modeledModuleInode':i+1}for i,n in enumerate(V.MODULES)}}
        custody=V.proven_custody(before,result,after)
        current={n:{'identity':after['modules'][n],'holders':['vfio_pci']if n=='vfio_pci_core'else[],
                    'refcnt':1 if n=='vfio_pci_core'else 0}for n in V.MODULES}
        return custody,current
    def test_only_named_proven_modules_removed_preexisting_dependencies_preserved(self):
        custody,current=self.custody();before=dict(custody['before']['dependencies'])
        commands=V.removal_plan(custody,current)
        self.assertEqual(commands,[[V.REMOVE,'vfio_pci'],[V.REMOVE,'vfio_pci_core']])
        # Explicit external-kernel MODEL applies each actual single-name command.
        loaded={'vfio_pci','vfio_pci_core','vfio','irqbypass'}
        for tool,name in commands:loaded.remove(name)
        self.assertEqual(loaded,{'vfio','irqbypass'});self.assertEqual(custody['before']['dependencies'],before)
    def test_partial_failed_or_foreign_module_ownership_refuses(self):
        for name in ('partial','failed','foreign-holder','inode-drift','foreign-ref'):
            with self.subTest(name=name):
                custody,current=self.custody()
                if name=='partial':custody['state']='ATTEMPTED'
                elif name=='failed':custody['state']='UNKNOWN'
                elif name=='foreign-holder':current['vfio_pci']['holders']=['foreign']
                elif name=='inode-drift':current['vfio_pci']['identity']={'foreign':True}
                else:current['vfio_pci']['refcnt']=2
                with self.assertRaises(ValueError):V.removal_plan(custody,current)
    def test_numeric_exit_alone_never_proves_initialization(self):
        custody,current=self.custody();before=custody['before'];after=custody['after']
        for key,value in [('numeric',1),('closure','UNKNOWN'),('EOF',False),('reaped',False),('primary',{'failure':True}),('secondary',[{'unknown':True}])]:
            bad=dict(custody['command']);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):V.proven_custody(before,bad,after)

if __name__=='__main__':unittest.main()
