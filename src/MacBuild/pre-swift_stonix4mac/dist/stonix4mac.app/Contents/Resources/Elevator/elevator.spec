# -*- mode: python -*-

block_cipher = None


a = Analysis(['elevator.py'],
             pathex=['/opt/tools/lib/Python/2.7/site-packages/PyQt5', '/opt/tools/Qt5.6.1/lib', '/opt/tools/lib/Python/2.7/site-packages', '/opt/tools/lib/Python/2.7/site-packages/sip/PyQt5', '/opt/tools/bin', '/usr/lib', '/Users/rsn/src/scratch/pyqt/dylan/current/external_20161004_0540-pyqt5/stonix/src/MacBuild/stonix4mac/Resources/Elevator'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='elevator',
          debug=True,
          strip=False,
          upx=False,
          console=False , icon='check.icns')
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=False,
               name='elevator')
app = BUNDLE(coll,
             name='elevator.app',
             icon='check.icns',
             bundle_identifier='gov.lanl.elevator')
