# github.com/ALTUSNETS\

This module creates static libraries---libipsec_ims.a.


WHAT IT DOES?
=============
It is used to establish ipsec tunnel.


HOW IT WAS BUILT?
==================
It needs the following library from AOSP:

libcutils libcrypto


All source/dependency modules of this module are already put in
'vendor/mediatek/proprietary/external/libipsec_ims' folder.

HOW TO USE IT?
==============

The library could be used by any deamon if deamon has included header file. In fact, the library is provided API for "vendor/mediatek/proprietary/frameworks/opt/volte"


