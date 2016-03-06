=====
Usage
=====

The library provides abstraction over DESFire command set. The communication with a NFC card must be done with an underlying library or API. DESFire provides adapters for different connection methods.

PCSC example (Linux)
====================

Below is an example how to interface with DESFire API using `pcscd <http://linux.die.net/man/8/pcscd>`_ daemon and `pycard library <http://pyscard.sourceforge.net/>`_:

.. code-block:: python

    #! /usr/bin/env python
    from __future__ import print_function

    import functools
    import logging
    import time
    import sys

    from smartcard.System import readers
    from smartcard.CardMonitoring import CardMonitor, CardObserver
    from smartcard.util import toHexString
    from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver

    from desfire.protocol import DESFire
    from desfire.pcsc import PCSCDevice

    #: Setup logging subsystem later
    logger = None


    IGNORE_EXCEPTIONS = (KeyboardInterrupt, MemoryError,)


    def catch_gracefully():
        """Function decorator to show any Python exceptions occured inside a function.

        Use when the underlying thread main loop does not provide satisfying exception output.
        """
        def _outer(func):

            @functools.wraps(func)
            def _inner(*args, **kwargs):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if isinstance(e, IGNORE_EXCEPTIONS):
                        raise
                    else:
                        logger.error("Catched exception %s when running %s", e, func)
                        logger.exception(e)

            return _inner

        return _outer


    class MyObserver(CardObserver):
        """Observe when a card is inserted. Then try to run DESFire application listing against it."""

        # We need to have our own exception handling for this as the
        # # main loop of pyscard doesn't seem to do any exception output by default
        @catch_gracefully()
        def update(self, observable, actions):

            (addedcards, removedcards) = actions

            for card in addedcards:
                logger.info("+ Inserted: %s", toHexString(card.atr))

                connection = card.createConnection()
                connection.connect()

                # This will log raw card traffic to console
                connection.addObserver(ConsoleCardConnectionObserver())

                # connection object itself is CardConnectionDecorator wrapper
                # and we need to address the underlying connection object
                # directly
                logger.info("Opened connection %s", connection.component)

                desfire = DESFire(PCSCDevice(connection.component))
                applications = desfire.get_applications()

                for app_id in applications:
                    logger.info("Found application 0x%06x", app_id)

                if not applications:
                    logger.info("No applications on the card")

            for card in removedcards:
                logger.info("- Removed: %s", toHexString(card.atr))


    def main():
        global logger

        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger(__name__)

        logger.info("Insert MIFARE Desfire card to any reader to get its applications.")

        available_reader = readers()
        logger.info("Available readers: %s", available_reader)
        if not available_reader:
            sys.exit("No smartcard readers detected")

        cardmonitor = CardMonitor()
        cardobserver = MyObserver()
        cardmonitor.addObserver(cardobserver)

        while True:
            time.sleep(1)

        # don't forget to remove observer, or the
        # monitor will poll forever...
        cardmonitor.deleteObserver(cardobserver)


    if __name__ == "__main__":
        main()
