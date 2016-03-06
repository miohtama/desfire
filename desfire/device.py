class Device(object):
    """Abstract base class which uses underlying device communication channel."""

    def transceive(self, bytes):
        """Send in APDU request and wait for the response.

        :param bytes: Outgoing bytes as list of bytes or byte array

        :return: List of bytes or byte array from the device.
        """
        raise NotImplementedError("Base class must implement")
