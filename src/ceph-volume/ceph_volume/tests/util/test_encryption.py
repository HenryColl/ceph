from ceph_volume.util import encryption
from unittest.mock import call, patch, Mock, MagicMock
from typing import Any
import base64
import pytest
import json
import re


class TestNoWorkqueue:
    def setup_method(self):
        encryption.conf.dmcrypt_no_workqueue = None

    @patch('ceph_volume.util.encryption.process.call',
           Mock(return_value=(['cryptsetup 2.7.2 flags: UDEV BLKID KEYRING' \
                               'FIPS KERNEL_CAPI PWQUALITY '], [''], 0)))
    def test_set_dmcrypt_no_workqueue_true(self):
        encryption.set_dmcrypt_no_workqueue()
        assert encryption.conf.dmcrypt_no_workqueue

    @patch('ceph_volume.util.encryption.process.call',
           Mock(return_value=(['cryptsetup 2.0.0'], [''], 0)))
    def test_set_dmcrypt_no_workqueue_false(self):
        encryption.set_dmcrypt_no_workqueue()
        assert encryption.conf.dmcrypt_no_workqueue is None

    @patch('ceph_volume.util.encryption.process.call',
           Mock(return_value=([''], ['fake error'], 1)))
    def test_set_dmcrypt_no_workqueue_cryptsetup_version_fails(self):
        with pytest.raises(RuntimeError):
            encryption.set_dmcrypt_no_workqueue()

    @patch('ceph_volume.util.encryption.process.call',
           Mock(return_value=(['unexpected output'], [''], 0)))
    def test_set_dmcrypt_no_workqueue_pattern_not_found(self):
        with pytest.raises(RuntimeError):
            encryption.set_dmcrypt_no_workqueue()

    @patch('ceph_volume.util.encryption.process.call',
           Mock(return_value=([], [''], 0)))
    def test_set_dmcrypt_no_workqueue_index_error(self):
        with pytest.raises(RuntimeError):
            encryption.set_dmcrypt_no_workqueue()


class TestBypassWorkqueue:
    def setup_method(self):
        encryption.conf.dmcrypt_no_workqueue = None

    @patch('ceph_volume.util.encryption.BackingDeviceRotation.is_rotational', return_value=False)
    def test_bypass_workqueue_non_rotational_no_workqueue_set(self, m_is_rotational):
        encryption.conf.dmcrypt_no_workqueue = True
        assert encryption.bypass_workqueue('/dev/nvme0n1') is True

    @patch('ceph_volume.util.encryption.BackingDeviceRotation.is_rotational', return_value=True)
    def test_bypass_workqueue_rotational_no_workqueue_set(self, m_is_rotational):
        encryption.conf.dmcrypt_no_workqueue = True
        assert encryption.bypass_workqueue('/dev/sda') is False

    @patch('ceph_volume.util.encryption.BackingDeviceRotation.is_rotational', return_value=False)
    def test_bypass_workqueue_non_rotational_no_workqueue_not_set(self, m_is_rotational):
        encryption.conf.dmcrypt_no_workqueue = None
        assert not encryption.bypass_workqueue('/dev/nvme0n1')


class TestGetKeySize(object):
    def test_get_size_from_conf_default(self, conf_ceph_stub):
        conf_ceph_stub('''
        [global]
        fsid=asdf
        ''')
        assert encryption.get_key_size_from_conf() == '512'

    def test_get_size_from_conf_custom(self, conf_ceph_stub):
        conf_ceph_stub('''
        [global]
        fsid=asdf
        [osd]
        osd_dmcrypt_key_size=256
        ''')
        assert encryption.get_key_size_from_conf() == '256'

    def test_get_size_from_conf_custom_invalid(self, conf_ceph_stub):
        conf_ceph_stub('''
        [global]
        fsid=asdf
        [osd]
        osd_dmcrypt_key_size=1024
        ''')
        assert encryption.get_key_size_from_conf() == '512'

class TestStatus(object):

    def test_skips_unuseful_lines(self, stub_call):
        out = ['some line here', '  device: /dev/sdc1']
        stub_call((out, '', 0))
        assert encryption.status('/dev/sdc1') == {'device': '/dev/sdc1'}

    def test_removes_extra_quotes(self, stub_call):
        out = ['some line here', '  device: "/dev/sdc1"']
        stub_call((out, '', 0))
        assert encryption.status('/dev/sdc1') == {'device': '/dev/sdc1'}

    def test_ignores_bogus_lines(self, stub_call):
        out = ['some line here', '  ']
        stub_call((out, '', 0))
        assert encryption.status('/dev/sdc1') == {}


class TestDmsetupRemove(object):

    def test_mapper_exists(self, fake_run, fake_filesystem):
        mapper_name = 'ceph-fsid-nvme2n2-block-dmcrypt'
        fake_filesystem.create_file('/dev/mapper/%s' % mapper_name)
        encryption.dmsetup_remove(mapper_name)
        arguments = fake_run.calls[0]['args'][0]
        assert arguments == ['dmsetup', 'remove', mapper_name]

    def test_mapper_does_not_exist(self, fake_run):
        encryption.dmsetup_remove('ceph-fsid-missing-block-dmcrypt')
        assert fake_run.calls == []


class TestDmcryptClose(object):

    def test_mapper_exists(self, fake_run, fake_filesystem):
        file_name = fake_filesystem.create_file('mapper-device')
        encryption.dmcrypt_close(file_name.path)
        arguments = fake_run.calls[0]['args'][0]
        assert arguments[0] == 'cryptsetup'
        assert arguments[1] == 'remove'
        assert arguments[2].startswith('/')

    def test_mapper_does_not_exist(self, fake_run):
        file_name = '/path/does/not/exist'
        encryption.dmcrypt_close(file_name)
        assert fake_run.calls == []


class TestDmcryptKey(object):

    def test_dmcrypt(self):
        result = encryption.create_dmcrypt_key()
        assert len(base64.b64decode(result)) == 128

class TestLuksFormat(object):
    @patch('ceph_volume.util.encryption.process.call')
    def test_luks_format_command_with_default_size(self, m_call, conf_ceph_stub):
        conf_ceph_stub('[global]\nfsid=abcd')
        expected = [
            'cryptsetup',
            '--batch-mode',
            '--key-size',
            '512',
            '--key-file',
            '-',
            'luksFormat',
            '/dev/foo'
        ]
        encryption.luks_format('abcd', '/dev/foo')
        assert m_call.call_args[0][0] == expected

    @patch('ceph_volume.util.encryption.process.call')
    def test_luks_format_with_extra_option(self, m_call, conf_ceph_stub):
        conf_ceph_stub('[global]\nfsid=abcd')
        expected = [
            'cryptsetup',
            '--batch-mode',
            '--key-size',
            '512',
            '--key-file',
            '-',
            'luksFormat',
            '--fake-custom-opt1',
            '/dev/foo'
        ]
        encryption.luks_format('abcd', '/dev/foo', '--fake-custom-opt1')
        assert m_call.call_args[0][0] == expected

    @patch('ceph_volume.util.encryption.process.call')
    def test_luks_format_command_with_custom_size(self, m_call, conf_ceph_stub):
        conf_ceph_stub('[global]\nfsid=abcd\n[osd]\nosd_dmcrypt_key_size=256')
        expected = [
            'cryptsetup',
            '--batch-mode',
            '--key-size',
            '256',
            '--key-file',
            '-',
            'luksFormat',
            '/dev/foo'
        ]
        encryption.luks_format('abcd', '/dev/foo')
        assert m_call.call_args[0][0] == expected


class TestLuksOpen(object):
    @patch('ceph_volume.util.encryption.bypass_workqueue', return_value=False)
    @patch('ceph_volume.util.encryption.process.call')
    def test_luks_open_command_with_default_size(self, m_call, m_bypass_workqueue, conf_ceph_stub):
        conf_ceph_stub('[global]\nfsid=abcd')
        expected = [
            'cryptsetup',
            '--key-size',
            '512',
            '--key-file',
            '-',
            '--allow-discards',
            'luksOpen',
            '/dev/foo',
            '/dev/bar'
        ]
        encryption.luks_open('abcd', '/dev/foo', '/dev/bar')
        assert m_call.call_args[0][0] == expected

    @patch('ceph_volume.util.encryption.bypass_workqueue', return_value=False)
    @patch('ceph_volume.util.encryption.process.call')
    def test_luks_open_command_with_custom_size(self, m_call, m_bypass_workqueue, conf_ceph_stub):
        conf_ceph_stub('[global]\nfsid=abcd\n[osd]\nosd_dmcrypt_key_size=256')
        expected = [
            'cryptsetup',
            '--key-size',
            '256',
            '--key-file',
            '-',
            '--allow-discards',
            'luksOpen',
            '/dev/foo',
            '/dev/bar'
        ]
        encryption.luks_open('abcd', '/dev/foo', '/dev/bar')
        assert m_call.call_args[0][0] == expected

    @patch('ceph_volume.util.encryption.bypass_workqueue', return_value=False)
    @patch('ceph_volume.util.encryption.process.call')
    def test_luks_format_with_extra_option(self, m_call, m_bypass_workqueue, conf_ceph_stub):
        conf_ceph_stub('[global]\nfsid=abcd')
        expected = [
            'cryptsetup',
            '--key-size',
            '512',
            '--key-file',
            '-',
            '--allow-discards',
            'luksOpen',
            '--fake-custom-opt1',
            '/dev/foo',
            '/dev/bar'
        ]
        encryption.luks_open('abcd', '/dev/foo', '/dev/bar', options='--fake-custom-opt1')
        assert m_call.call_args[0][0] == expected

    @patch('ceph_volume.util.encryption.bypass_workqueue', return_value=False)
    @patch('ceph_volume.util.encryption.process.call')
    def test_luks_open_command_with_tpm(self, m_call, m_bypass_workqueue, conf_ceph_stub):
        fake_mapping: str = 'fake-mapping'
        fake_device: str = 'fake-device'
        expected = [
            '/usr/lib/systemd/systemd-cryptsetup',
            'attach',
            fake_mapping,
            fake_device,
            '-',
            'tpm2-device=auto,discard,headless=true,nofail',
        ]
        encryption.luks_open('', fake_device, fake_mapping, 1)
        assert m_call.call_args[0][0] == expected

    @patch('ceph_volume.util.encryption.bypass_workqueue', return_value=True)
    @patch('ceph_volume.util.encryption.process.call')
    def test_luks_open_command_with_tpm_bypass_workqueue(self, m_call, m_bypass_workqueue, conf_ceph_stub):
        fake_mapping: str = 'fake-mapping'
        fake_device: str = 'fake-device'
        expected = [
            '/usr/lib/systemd/systemd-cryptsetup',
            'attach',
            fake_mapping,
            fake_device,
            '-',
            'tpm2-device=auto,discard,headless=true,nofail,no-read-workqueue,no-write-workqueue',
        ]
        encryption.luks_open('', fake_device, fake_mapping, 1)
        assert m_call.call_args[0][0] == expected


class TestCephLuks2:
    @patch.object(encryption.CephLuks2, 'get_osd_fsid', Mock(return_value='abcd-1234'))
    @patch.object(encryption.CephLuks2, 'is_ceph_encrypted', Mock(return_value=True))
    def test_init_ceph_encrypted(self) -> None:
        assert encryption.CephLuks2('/dev/foo').osd_fsid == 'abcd-1234'

    @patch.object(encryption.CephLuks2, 'get_osd_fsid', Mock(return_value=''))
    @patch.object(encryption.CephLuks2, 'is_ceph_encrypted', Mock(return_value=False))
    def test_init_not_ceph_encrypted(self) -> None:
        assert encryption.CephLuks2('/dev/foo').osd_fsid == ''

    def test_has_luks2_signature(self) -> None:
        with patch('ceph_volume.util.encryption._dd_read', return_value='LUKS'):
            assert encryption.CephLuks2('/dev/foo').has_luks2_signature

    @patch('ceph_volume.util.encryption._dd_read', side_effect=Exception('foo'))
    def test_has_luks2_signature_raises_exception(self, m_dd_read: Any) -> None:
        with pytest.raises(RuntimeError):
            encryption.CephLuks2('/dev/foo').has_luks2_signature

    @patch.object(encryption.CephLuks2, 'get_subsystem', Mock(return_value='ceph_fsid=abcd'))
    @patch.object(encryption.CephLuks2, 'has_luks2_signature', Mock(return_value=True))
    def test_is_ceph_encrypted(self) -> None:
        assert encryption.CephLuks2('/dev/foo').is_ceph_encrypted

    @patch.object(encryption.CephLuks2, 'get_label', Mock(return_value=''))
    @patch.object(encryption.CephLuks2, 'has_luks2_signature', Mock(return_value=True))
    def test_is_not_ceph_encrypted(self) -> None:
        assert not encryption.CephLuks2('/dev/foo').is_ceph_encrypted

    @patch('ceph_volume.util.encryption.process.call', Mock(return_value=MagicMock()))
    def test_config_luks2_invalid_config(self) -> None:
        with pytest.raises(RuntimeError):
            encryption.CephLuks2('/dev/foo').config_luks2({'subsystem': 'ceph_fsid=1234-abcd', 'label': 'foo', 'foo': 'bar'})

    @patch('ceph_volume.util.encryption.process.call', Mock(return_value=MagicMock()))
    def test_config_luks2_invalid_config_keys(self) -> None:
        with pytest.raises(RuntimeError):
            encryption.CephLuks2('/dev/foo').config_luks2({'fake': 'fake-value', 'subsystem': 'ceph_fsid=1234-abcd'})

    @patch('ceph_volume.util.encryption.process.call')
    def test_config_luks2_ok(self, m_call: Any) -> None:
        m_call.return_value = ('', '', 0)
        encryption.CephLuks2('/dev/foo').config_luks2({'label': 'foo', 'subsystem': 'ceph_fsid=1234-abcd'})
        assert m_call.mock_calls == [call(['cryptsetup', 'config', '/dev/foo', '--label', 'foo', '--subsystem', 'ceph_fsid=1234-abcd'], verbose_on_failure=False)]

    @patch('ceph_volume.util.encryption.process.call')
    def test_config_luks2_raises_exception(self, m_call: Any) -> None:
        m_call.return_value = ('', '', 1)
        with pytest.raises(RuntimeError):
            encryption.CephLuks2('/dev/foo').config_luks2({'label': 'foo', 'subsystem': 'ceph_fsid=1234-abcd'})

    def test_get_label(self) -> None:
        with patch('ceph_volume.util.encryption._dd_read', return_value='fake-luks2-label'):
            label: str = encryption.CephLuks2('/dev/foo').get_label()
            assert label == 'fake-luks2-label'

    def test_get_label_raises_exception(self) -> None:
        with patch('ceph_volume.util.encryption._dd_read', side_effect=Exception('fake-error')):
            with pytest.raises(RuntimeError):
                encryption.CephLuks2('/dev/foo').get_label()

    @patch.object(encryption.CephLuks2, 'get_subsystem', Mock(return_value='ceph_fsid=abcd'))
    def test_get_osd_fsid(self) -> None:
        assert encryption.CephLuks2('/dev/foo').get_osd_fsid() == 'abcd'

    @patch.object(encryption.CephLuks2, 'get_label', Mock(return_value='ceph'))
    def test_get_osd_fsid_error(self) -> None:
        result: str = encryption.CephLuks2('/dev/foo').get_osd_fsid()
        assert result == ''

    def test_get_subsystem(self) -> None:
        with patch('ceph_volume.util.encryption._dd_read', return_value='fake-luks2-subsystem'):
            assert encryption.CephLuks2('/dev/foo').get_subsystem() == 'fake-luks2-subsystem'

    def test_get_subsystem_raises_exception(self) -> None:
        with patch('ceph_volume.util.encryption._dd_read', side_effect=Exception('fake-error')):
            with pytest.raises(RuntimeError):
                encryption.CephLuks2('/dev/foo').get_subsystem()

    def test_get_json_area(self) -> None:
        mock_json_data = '{"tokens": {"1": {"type": "systemd-tpm2"}}}'
        with patch('ceph_volume.util.encryption._dd_read', return_value=mock_json_data):
            assert encryption.CephLuks2('/dev/foo').get_json_area() == json.loads(mock_json_data)

    def test_get_json_area_invalid(self) -> None:
        with patch('ceph_volume.util.encryption._dd_read', return_value='invalid-json-data'):
            with pytest.raises(RuntimeError):
                encryption.CephLuks2('/dev/foo').get_json_area()

    def test_get_json_area_exception_caught(self) -> None:
        with patch('ceph_volume.util.encryption._dd_read', side_effect=OSError):
            with pytest.raises(OSError):
                encryption.CephLuks2('/dev/foo').get_json_area()

    @patch('ceph_volume.util.encryption.lsblk', Mock(return_value={'FSTYPE': 'crypto_LUKS'}))
    @patch.object(encryption.CephLuks2, 'get_json_area', Mock(return_value={"tokens": {"1": {"type": "systemd-tpm2"}}}))
    def test_is_tpm2_enrolled_true(self) -> None:
        assert encryption.CephLuks2('/dev/foo').is_tpm2_enrolled

    @patch('ceph_volume.util.encryption.lsblk', Mock(return_value={'FSTYPE': 'whatever'}))
    def test_is_tpm2_enrolled_false_not_a_luks_device(self) -> None:
        assert not encryption.CephLuks2('/dev/foo').is_tpm2_enrolled

    @patch('ceph_volume.util.encryption.lsblk', Mock(return_value={'FSTYPE': 'crypto_LUKS'}))
    @patch.object(encryption.CephLuks2, 'get_json_area', Mock(return_value={"whatever": "fake-value"}))
    def test_is_tpm2_enrolled_false_not_enrolled_with_tpm2(self) -> None:
        assert not encryption.CephLuks2('/dev/foo').is_tpm2_enrolled


class TestSedFormat:
    """Tests for encryption.sed_format()"""

    def _make_call(self, rc=0, out=None):
        """Return a process.call mock that always returns (out or [], [], rc)."""
        return Mock(return_value=(out or [], [], rc))

    @patch('ceph_volume.util.encryption._sed_query_locking_enabled', return_value=False)
    @patch('ceph_volume.util.encryption.process.call')
    def test_clean_drive_does_not_revert(self, m_call, m_query):
        """A drive with locking not yet enabled skips the WKK revert step."""
        m_call.return_value = ([], [], 0)
        encryption.sed_format('admin1secret', '/dev/sda')
        # No --revertTPer call should be present
        calls_flat = [' '.join(c[0][0]) for c in m_call.call_args_list]
        assert not any('revertTPer' in c for c in calls_flat)

    @patch('ceph_volume.util.encryption._sed_query_locking_enabled', return_value=True)
    @patch('ceph_volume.util.encryption.process.call')
    def test_clean_drive_provisioning(self, m_call, m_query):
        """initialSetup → setAdmin1Password → enableLockingRange are called in order,
        WKK is passed to --initialSetup, and admin1_key is forwarded to --setAdmin1Password."""
        m_call.return_value = ([], [], 0)
        encryption.sed_format('admin1secret', '/dev/sda')
        calls = [c[0][0] for c in m_call.call_args_list]
        subcommands = [cmd[1] for cmd in calls]
        assert subcommands == ['--revertTPer', '--initialSetup', '--setAdmin1Password', '--enableLockingRange']
        setup_call = next(cmd for cmd in calls if '--initialSetup' in cmd)
        assert encryption.SED_WKK in setup_call
        set_pw_call = next(cmd for cmd in calls if '--setAdmin1Password' in cmd)
        assert 'admin1secret' in set_pw_call

    @patch('ceph_volume.util.encryption._sed_query_locking_enabled', return_value=True)
    @patch('ceph_volume.util.encryption.process.call')
    def test_already_locked_unknown_sid_raises(self, m_call, m_query):
        """WKK revert fails (unknown SID) → RuntimeError; no further calls made."""
        # revertTPer returns rc=1, everything else returns rc=0
        def side_effect(cmd, **kwargs):
            if '--revertTPer' in cmd:
                return ([], ['auth failure'], 1)
            return ([], [], 0)
        m_call.side_effect = side_effect
        with pytest.raises(RuntimeError, match=re.escape("sedutil-cli --revertTPer failed on /dev/sda: ['auth failure']")):
            encryption.sed_format('admin1secret', '/dev/sda')
        # Only the revertTPer call should have been made
        subcommands = [c[0][0][1] for c in m_call.call_args_list]
        assert '--initialSetup' not in subcommands

    @patch('ceph_volume.util.encryption._sed_query_locking_enabled', return_value=False)
    @patch('ceph_volume.util.encryption.process.call')
    def test_no_cryptsetup_calls(self, m_call, m_query):
        """SED format must not invoke cryptsetup at all."""
        m_call.return_value = ([], [], 0)
        encryption.sed_format('admin1secret', '/dev/sda')
        for c in m_call.call_args_list:
            assert 'cryptsetup' not in c[0][0][0]


class TestSedOpen:
    """Tests for encryption.sed_open()"""

    @patch('ceph_volume.util.encryption.process.call')
    def test_calls_setLockingRange_RW(self, m_call):
        m_call.return_value = ([], [], 0)
        encryption.sed_open('admin1secret', '/dev/sda')
        args = m_call.call_args[0][0]
        assert args[:5] == ['sedutil-cli', '--setLockingRange', '0', 'RW', 'admin1secret']
        assert args[5] == '/dev/sda'

    @patch('ceph_volume.util.encryption.process.call')
    def test_raises_on_failure(self, m_call):
        m_call.return_value = ([], ['error'], 1)
        with pytest.raises(RuntimeError, match='setLockingRange'):
            encryption.sed_open('admin1secret', '/dev/sda')


class TestSedQueryLockingEnabled:
    """Tests for encryption._sed_query_locking_enabled()"""

    @patch('ceph_volume.util.encryption.process.call')
    def test_returns_true_when_locking_enabled(self, m_call):
        m_call.return_value = (['LockingEnabled = Y'], [], 0)
        assert encryption._sed_query_locking_enabled('/dev/sda') is True

    @patch('ceph_volume.util.encryption.process.call')
    def test_returns_false_when_locking_not_enabled(self, m_call):
        m_call.return_value = (['Locking function enabled = N'], [], 0)
        assert encryption._sed_query_locking_enabled('/dev/sda') is False
