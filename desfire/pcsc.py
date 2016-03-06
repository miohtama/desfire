from smartcard.pcsc.PCSCCardConnection import translateprotocolheader
from smartcard.scard import SCardTransmit
from smartcard.scard import SCardGetErrorMessage
from smartcard.Exceptions import CardConnectionException

from .device import Device


class PCSCNotConnected(Exception):
    """Tried to transmit to non-open connection."""


class PCSCDevice(Device):
    """DESFire protocol wrapper for pyscard interface."""

    def __init__(self, card_connection):
        """
        :card_connection: :py:class:`smartcard.pcsc.PCSCCardConnection.PCSCCardConnection` instance. Call ``card_connection.connect()`` before calling any DESFire APIs.
        """
        self.card_connection = card_connection

    def transceive(self, bytes):

        if not self.card_connection.hcard:
            raise PCSCNotConnected("Tried to transit to non-open connection: {}".format(self.card_connection))

        protocol = self.card_connection.getProtocol()
        pcscprotocolheader = translateprotocolheader(protocol)

        # http://pyscard.sourceforge.net/epydoc/smartcard.scard.scard-module.html#SCardTransmit
        hresult, response = SCardTransmit(self.card_connection.hcard, pcscprotocolheader, bytes)

        if hresult != 0:
            raise CardConnectionException('Failed to transmit with protocol ' + str(pcscprotocolheader) + '. ' + SCardGetErrorMessage(hresult))
        return response
