.. highlight:: shell

============
Installation
============

Install with pip to your virtualenv.

Ubuntu Linux
------------

Install libraries using a `Python virtual environment <https://packaging.python.org/en/latest/installing/#optionally-create-a-virtual-environment>`_.

You need `pyscard <https://pypi.python.org/pypi/pyscard>`_ and it's dependencies. For Ubuntu:

.. code-block:: console

    apt install swig swig3.0 libpcsclite-dev pcscd

*pyscard* must be installed by hand (see `issue <https://github.com/LudovicRousseau/pyscard/issues/15>`_):

.. code-block:: console

    # Need github registerd SSH pubkey
    git clone git@github.com:LudovicRousseau/pyscard.git
    cd pyscard
    python setup.py develop

Then install desfire:

.. code-block:: console

    pip install desfire

Android and Kivy
----------------

TODO
