import logging

import pytest

from desfire.dummy import DummyDevice
from desfire.protocol import DESFire
from desfire.protocol import DESFireCommunicationError

@pytest.fixture
def device():
    return DummyDevice()


@pytest.fixture
def desfire(device):
    logger = logging.getLogger("test")
    logger.setLevel(logging.ERROR)
    return DESFire(device, logger)



def test_invalid_response(desfire, device):
    """We raise error on invalid response."""
    device.test_reply = [0x00, 0x00]
    with pytest.raises(DESFireCommunicationError):
        list_applications = desfire.get_applications()


def test_select_application(desfire, device):
    """Application listing gives correct result for one application."""
    device.test_reply = [0x01, 0x02, 0x03, 0x91, 0x00]
    list_applications = desfire.get_applications()
    assert len(list_applications) == 1
    assert list_applications[0] == 0x010203
