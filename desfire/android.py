# -*- coding: utf-8 -*-


from .device import Device


class AndroidDevice(Device):
    """DESFire protocol wrapper for pyscard interface."""

    def __init__(self, iso_dep):
        """
        :iso_dep: ``android.nfc.tech.IsoDep`` Java class wrapped as jnius object.
        """
        self.iso_dep = iso_dep

    def transceive(self, bytes):
        """

         .. note ::
            Android API may return byte array memory views that are easily corrupted by native APIs, so we just copy all incoming bytes to a proper list as soon as possible on Android.

        """
        return list(self.iso_dep.transceive(bytes))
