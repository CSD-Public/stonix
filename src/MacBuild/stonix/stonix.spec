# -*- mode: python -*-
a = Analysis(['stonix.py'],
             pathex=['stonix_resources/rules:stonix_resources', '/private/tmp/ekoch.PaX1q7/src/MacBuild/stonix'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=[])
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='stonix',
          debug=False,
          strip=True,
          upx=False,
          console=False , icon='../stonix_icon.icns')
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=True,
               upx=False,
               name='stonix')
app = BUNDLE(coll,
             name='stonix.app',
             icon='../stonix_icon.icns')
