The Bot
=======

The magic happens in the :class:`wxc_cc_bot.CallControlBot` class.

A :class:`wxc_cc_bot.CallControlBot` instance is created in :func:`wxc_cc_bot.create_app`. When running locally
:func:`wxc_cc_bot.create_app` is called from within the main code of ``wxc_cc_bot.py``. When run on Heroku
:func:`wxc_cc_bot.create_app` is referenced in the Procfile:

.. literalinclude:: ../Procfile

The bot class:

.. autoclass:: wxc_cc_bot.CallControlBot
    :class-doc-from: both
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:


