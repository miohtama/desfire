
from .device import Device


class DummyDevice(Device):
    """Dummy device mock implementation."""

    def __init__(self):
        # Unit tests may set for outgoing reply
        self.test_reply = [0x90, 0x00]

    def transceive(self, bytes):
        # Always return a
        return self.test_reply
