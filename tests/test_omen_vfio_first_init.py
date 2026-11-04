"""Pure option lifetime decision; no Root, device or VM acceptance claimed."""
import importlib.util
from pathlib import Path
import unittest

SPEC=importlib.util.spec_from_file_location('managed_vfio',Path(__file__).parents[1]/'scripts/omen_control/managed_vfio.py')
V=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(V)

class FirstInitializationTests(unittest.TestCase):
    def test_unloaded_driver_and_core_use_existing_first_initialization(self):
        self.assertEqual(V.initial_plan({'vfio_pci':False,'vfio_pci_core':False}),
            ['/usr/sbin/modprobe','--ignore-install','--first-time','vfio-pci','disable_idle_d3=1'])
    def test_loaded_or_unknown_option_lifetime_never_reloads(self):
        for state in ({'vfio_pci':True,'vfio_pci_core':True},
                      {'vfio_pci':False,'vfio_pci_core':True},
                      {'vfio_pci':True,'vfio_pci_core':False},
                      {'vfio_pci':0,'vfio_pci_core':False},{'vfio_pci':False},{}):
            with self.subTest(state=state),self.assertRaises(ValueError):V.initial_plan(state)

if __name__=='__main__':unittest.main()
