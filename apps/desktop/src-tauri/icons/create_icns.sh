#!/bin/bash
# Create .icns from iconset
cd "$(dirname "$0")"
iconutil -c icns icon.iconset -o icon.icns 2>&1
if [ $? -ne 0 ]; then
    echo "iconutil failed, trying alternative method..."
    # Try using the macOS native approach
    /usr/bin/iconutil -c icns icon.iconset -o icon.icns
fi
