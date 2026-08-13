from __future__ import print_function
import logging
import argparse
import os
import shutil
from textwrap import dedent
from ceph_volume import objectstore, terminal
from .common import prepare_parser
from typing import List, Optional

logger = logging.getLogger(__name__)


class Prepare(object):

    help = 'Format an LVM device and associate it with an OSD'

    def __init__(self, argv: Optional[List[str]] = None, args: Optional[argparse.Namespace] = None) -> None:
        self.objectstore: Optional[objectstore.baseobjectstore.BaseObjectStore] = None
        self.argv = argv
        self.args = args
        self.osd_id = None

    def main(self) -> None:
        sub_command_help = dedent("""
        Prepare an OSD by assigning an ID and FSID, registering them with the
        cluster with an ID and FSID, formatting and mounting the volume, and
        finally by adding all the metadata to the logical volumes using LVM
        tags, so that it can later be discovered.

        Once the OSD is ready, an ad-hoc systemd unit will be enabled so that
        it can later get activated and the OSD daemon can get started.

        Encryption is supported via dmcrypt and the --dmcrypt flag.

        Existing logical volume (lv):

            ceph-volume lvm prepare --data {vg/lv}

        Existing block device (a logical volume will be created):

            ceph-volume lvm prepare --data /path/to/device

        Optionally, can consume db and wal devices, partitions or logical
        volumes. A device will get a logical volume, partitions and existing
        logical volumes will be used as is:

            ceph-volume lvm prepare --data {vg/lv} --block.wal {partition} --block.db {/path/to/device}
        """)
        parser = prepare_parser(
            prog='ceph-volume lvm prepare',
            description=sub_command_help,
        )
        if self.argv is None:
            self.argv = []
        if len(self.argv) == 0 and self.args is None:
            print(sub_command_help)
            return
        if self.args is None:
            self.args = parser.parse_args(self.argv)
        if self.args.bluestore:
            self.args.objectstore = 'bluestore'
        if self.args.sed and self.args.dmcrypt:
            terminal.error('--SED and --dmcrypt are mutually exclusive')
            raise SystemExit(1)

        if self.args.sed and not shutil.which('sedutil-cli'):
            terminal.error('--SED requires sedutil-cli to be installed '
                           '(available via EPEL)')
            raise SystemExit(1)

        self.objectstore = objectstore.mapping['LVM'][self.args.objectstore](args=self.args)
        if self.objectstore is not None:
            self.objectstore.safe_prepare()
        else:
            raise RuntimeError('Unexpected error while setting objectore backend.')
