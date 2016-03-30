=========================
MIFARE DESFire for Python
=========================

.. image:: https://img.shields.io/pypi/v/desfire.svg
        :target: https://pypi.python.org/pypi/desfire

.. image:: https://img.shields.io/travis/miohtama/desfire.svg
        :target: https://travis-ci.org/miohtama/desfire

.. image:: https://readthedocs.org/projects/desfire/badge/?version=latest
        :target: https://readthedocs.org/projects/desfire/?badge=latest
        :alt: Documentation Status


This package provides `MIFARE DESFire <https://en.wikipedia.org/wiki/MIFARE>`_ native communication protocol for NFC cards.

Source code: https://github.com/miohtama/desfire

Documentation: https://desfire.readthedocs.org

.. image:: https://raw.githubusercontent.com/miohtama/desfire/master/docs/desfire.jpg

*In photo: MIFARE DESFire EV1 8kB blank card with Identive CLOUD 4500 F Dual Interface Reader*

Features
--------

* Compatibile with USB-based NFC readers via PCSC interface. PCSC API is available on Linux, OSX and Windows. Linux support includes support for Raspberry Pi.

* Compatibile with Android mobile phones and their built-in NFC readers. This is done using `Kivy <https://kivy.org/>`_ cross application Python framework and native Android APIs via `pyjnius <https://github.com/kivy/pyjnius>`_ Python to Java bridging.

* Only some of the commands are implemented in the current alpha quality version, please feel free to add more.

* Compatible with Python 2 and Python 3

Background
----------

`The communication protocol specification is not public <http://stackoverflow.com/a/24069446/315168>`_. The work is based on reverse engineering existing open source DESFire projects, namely `Android host card emulation for DESFire <https://github.com/jekkos/android-hce-desfire>`_ and `MIFARE SDK <https://www.mifare.net/en/products/tools/mifare-sdk/>`_.

Author
------

`Mikko Ohtamaa <https://opensourcehacker.com>`_.

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
