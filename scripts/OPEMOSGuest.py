"""Robot observations inside an admitted non-graphical guest role."""
import json
import os
from pathlib import Path
import platform

class OPEMOSGuest:
    ROBOT_AUTO_KEYWORDS=False
    def get_keyword_names(self):return ['Verify Current Guest Identity']
    def run_keyword(self,name,args,kwargs=None):
        assert name=='Verify Current Guest Identity'
        # Exact expected boot/kernel comes from the normal admitted queue job,
        # not from an old receipt or an unrelated outer imaging host.
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        assert boot==os.environ['OPEMOS_EXPECTED_BOOT_ID']
        kernel=platform.release();assert kernel==os.environ['OPEMOS_EXPECTED_KERNEL']
        assert os.environ['OPEMOS_SUBJECT_ROLE']in ('nested_linux','fedora_appliance','virtual_usb')
        return {'boot_id':boot,'kernel':kernel,'subject_role':os.environ['OPEMOS_SUBJECT_ROLE'],'gui_claim':False}
