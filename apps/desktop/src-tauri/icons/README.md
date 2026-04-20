# Desktop Icon Assets

This directory contains the icon files used by the HybridCipher desktop bundle.

The Tauri bundle configuration in [`../tauri.conf.json`](../tauri.conf.json) currently references these files:

- `32x32.png`
- `128x128.png`
- `128x128@2x.png`
- `icon.icns`

## Source and generated assets

- `icon.png` and `icon-1024.png`: raster source assets used when preparing bundle icons
- `icon.iconset/`: macOS iconset used to generate `icon.icns`
- `create_icns.sh`: helper script that rebuilds `icon.icns` from `icon.iconset/`

## Updating the icon set

1. Replace or update the source artwork in this directory.
2. Regenerate the PNG and ICNS outputs so the filenames referenced by `../tauri.conf.json` still exist.
3. On macOS, run `./create_icns.sh` from this directory to rebuild `icon.icns` from `icon.iconset/`.
4. Recheck `../tauri.conf.json` after changes so the bundle still points at the correct icon files.

`temp_1024.png` is a working asset in this directory and is not referenced directly by the Tauri bundle config.
