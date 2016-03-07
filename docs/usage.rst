=====
Usage
=====

The library provides abstraction over DESFire command set. The communication with a NFC card must be done with an underlying library or API. DESFire provides adapters for different connection methods.

* Create a native connection to NFC card using underlying libraries

* Wrap this connection to proper adapter as :py:class:`desfire.device.Device` subclass

* Create a :py:class:`desfire.protocol.DESFire` object for the device

* Use :py:class:`desfire.protocol.DESFire` API methods

PCSC example
============

Below is an example how to interface with DESFire API using `pcscd <http://linux.die.net/man/8/pcscd>`_ daemon and `pycard library <http://pyscard.sourceforge.net/>`_. It should work on OSX, Linux and Windows including Raspberry Pi:

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

Continuous card connection
==========================

Here is another more advanced example. When the card is attached to the reader, keep connecting to the card continuously and decrease it's stored value file 1 credit per second until we have consumed all the credit.

.. code-block:: python

    #! /usr/bin/env python
    from __future__ import print_function

    import functools
    import logging
    import time
    import sys
    import threading

    from rainbow_logging_handler import RainbowLoggingHandler

    from smartcard.System import readers
    from smartcard.CardMonitoring import CardMonitor, CardObserver
    from smartcard.util import toHexString
    from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
    from smartcard.Exceptions import CardConnectionException

    from desfire.protocol import DESFire
    from desfire.pcsc import PCSCDevice

    #: Setup logging subsystem later
    logger = None


    IGNORE_EXCEPTIONS = (KeyboardInterrupt, MemoryError,)


    FOOBAR_APP_ID = 0x121314
    FOOBAR_STORED_VALUE_FILE_ID = 0x01

    #: FOOBAR consumer thread
    consumer = None


    def setup_logging():

        # Setup Python root logger to DEBUG level
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter("[%(asctime)s] %(name)s %(funcName)s():%(lineno)d\t%(message)s")  # same as default

        # Add colored log handlign to sys.stderr
        handler = RainbowLoggingHandler(sys.stderr)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

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



    class ConsumerThread(threading.Thread):
        """Keep debiting down stored value file on the card until its done."""

        def __init__(self):
            super(ConsumerThread, self).__init__()

            #: Array of cards with open connection in connection attribute
            self.cards = set()
            self.alive = True

        def attach_card(self, card):
            self.cards.add(card)

        def detach_card(self, card):
            if card in self.cards:
                self.cards.remove(card)

        @catch_gracefully()
        def run(self):

            while self.alive:

                # List of cards where we have lost connetion
                remove_cards = []

                for card in self.cards:
                    card_id = toHexString(card.atr)
                    desfire = DESFire(PCSCDevice(card.connection))
                    try:
                        desfire.select_application(FOOBAR_APP_ID)
                        value = desfire.get_value(FOOBAR_STORED_VALUE_FILE_ID)
                        if value > 0:
                            logger.info("Card: %s value left: %d", card_id, value)
                            desfire.debit_value(FOOBAR_STORED_VALUE_FILE_ID, 1)
                            desfire.commit()
                        else:
                            logger.info("No value left on card: %s", card_id)

                    except CardConnectionException:
                        # Lost the card in the middle of transit
                        logger.warn("Consumer lost the card %s", card_id)
                        remove_cards.append(card)
                    finally:
                        pass

                for c in remove_cards:
                    card_id = toHexString(card.atr)
                    logger.debug("Consumer removing a bad card from itself: %s", card_id)
                    self.detach_card(c)

                time.sleep(1)


    class MyObserver(CardObserver):
        """Observe when a card is inserted. Then try to run DESFire application listing against it."""

        @catch_gracefully()
        def update(self, observable, actions):

            (addedcards, removedcards) = actions

            for card in addedcards:
                logger.info("+ Inserted: %s", toHexString(card.atr))

                connection = card.createConnection()
                connection.connect()
                card.connection = connection.component

                # This will log raw card traffic to console
                connection.addObserver(ConsoleCardConnectionObserver())

                # connection object itself is CardConnectionDecorator wrapper
                # and we need to address the underlying connection object
                # directly
                logger.debug("Opened connection %s", connection.component)

                desfire = DESFire(PCSCDevice(connection.component))
                applications = desfire.get_applications()

                if FOOBAR_APP_ID in applications:
                    consumer.attach_card(card)
                else:
                    logger.warn("DESFire card doesn't have the required application. Maybe not properly formatted?")

            for card in removedcards:
                logger.info("- Removed: %s", toHexString(card.atr))
                consumer.detach_card(card)


    def main():
        global logger
        global consumer

        setup_logging()
        logger = logging.getLogger(__name__)

        logger.info("Insert MIFARE Desfire card to any reader to get its applications.")

        available_reader = readers()
        logger.info("Available readers: %s", available_reader)
        if not available_reader:
            sys.exit("No smartcard readers detected")

        consumer = ConsumerThread()
        consumer.start()

        cardmonitor = CardMonitor()
        cardobserver = MyObserver()
        cardmonitor.addObserver(cardobserver)

        try:
            while True:
                time.sleep(1)
        finally:
            consumer.alive = False

        # don't forget to remove observer, or the
        # monitor will poll forever...
        cardmonitor.deleteObserver(cardobserver)


    if __name__ == "__main__":
        main()
