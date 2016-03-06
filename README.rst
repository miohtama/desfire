===============================
Desfire for Python
===============================

.. image:: https://img.shields.io/pypi/v/desfire.svg
        :target: https://pypi.python.org/pypi/desfire

.. image:: https://img.shields.io/travis/miohtama/desfire.svg
        :target: https://travis-ci.org/miohtama/desfire

.. image:: https://readthedocs.org/projects/desfire/badge/?version=latest
        :target: https://readthedocs.org/projects/desfire/?badge=latest
        :alt: Documentation Status


This package provide Mifare DESFire communication protocol for NFC cards.

* Free software: ISC license
* Documentation: https://desfire.readthedocs.org.

Features
--------

* Compatibile with Linux and USB-based NFC readers via pcscd

* Compatibile with Android and Kivy via native Android APIs

* Only some of the commands are implemented, please feel free to add more

Background
----------

This package provides `MIFare DESFire <https://en.wikipedia.org/wiki/MIFARE>`_ native communication protocol for NFC cards.

`The communication protocol specification is not public <http://stackoverflow.com/a/24069446/315168>`_. The work is based on reverse engineering existing open source DESFire projects, namely `Android host card emulation for DESFire <https://github.com/jekkos/android-hce-desfire>`_ and `Mifare SDK <https://www.mifare.net/en/products/tools/mifare-sdk/>`_.

Author
------

`Mikko Ohtamaa <https://opensourcehacker.com>`_.

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
