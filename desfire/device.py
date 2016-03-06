

class Device(object):
    """Abstract base class which uses underlying device communication channel."""


    def transceive(self, bytes):
        """Send it request


        :param bytes: Outgoing bytes as list of bytes or byte array
        :return: List of bytes or byte array from the device. If you expect list slicing operations explicity convert the return value to a list with ``list()``.
        """
        raise NotImplementedError("Base class must implement")
