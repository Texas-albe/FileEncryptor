# Copyright (C) 2024 The Qt Company Ltd.
# SPDX-License-Identifier: BSD-3-Clause

set(__standalone_parts_qt_packages_args
    QT_MODULE_PACKAGES
        EntryPointPrivate
        Core
        PngPrivate
        JpegPrivate
        FreetypePrivate
        HarfbuzzPrivate
        Concurrent
        Network
        Xml
        DBus
        Gui
        ExampleIconsPrivate
        ExamplesAssetDownloaderPrivate
        OpenGL
        Widgets
        OpenGLWidgets
        DeviceDiscoverySupportPrivate
        FbSupportPrivate
        TestInternalsPrivate
        Test
        PrintSupport
)
qt_internal_find_standalone_parts_qt_packages(__standalone_parts_qt_packages_args)
