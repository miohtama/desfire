==================
Desfire for Python
==================

.. image:: https://img.shields.io/pypi/v/desfire.svg
        :target: https://pypi.python.org/pypi/desfire

.. image:: https://img.shields.io/travis/miohtama/desfire.svg
        :target: https://travis-ci.org/miohtama/desfire

.. image:: https://readthedocs.org/projects/desfire/badge/?version=latest
        :target: https://readthedocs.org/projects/desfire/?badge=latest
        :alt: Documentation Status


This package provide MIFARE DESFire communication protocol for NFC cards using Python.

Documentation: https://desfire.readthedocs.org.

Features
--------

* Compatibile with USB-based NFC readers via PCSC interface. PCSC API is available on Linux, OSX and Windows. Linux support includes support for Raspberry Pi.

* Compatibile with Android mobile phones and their built-in NFC readers. This is done using `Kivy <https://kivy.org/>`_ cross application Python framework and native Android APIs via `pyjnius <https://github.com/kivy/pyjnius>`_ Python to Java bridging.

* Only some of the commands are implemented, please feel free to add more

Background
----------

This package provides `MIFARE DESFire <https://en.wikipedia.org/wiki/MIFARE>`_ native communication protocol for NFC cards.

`The communication protocol specification is not public <http://stackoverflow.com/a/24069446/315168>`_. The work is based on reverse engineering existing open source DESFire projects, namely `Android host card emulation for DESFire <https://github.com/jekkos/android-hce-desfire>`_ and `Mifare SDK <https://www.mifare.net/en/products/tools/mifare-sdk/>`_.

Author
------

`Mikko Ohtamaa <https://opensourcehacker.com>`_.

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
