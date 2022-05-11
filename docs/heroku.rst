Running on Heroku
=================

Deployment on Heroku is controlled by:

* ``Procfile``: defines worker type and command to start a worker

    .. literalinclude:: ../Procfile

* ``runtime.txt``: Python version specification

    .. literalinclude:: ../runtime.txt

* ``requirements.txt``: list of module dependencies which need to be installed

    .. literalinclude:: ../requirements.txt

The Git repository is pushed to Heroku for deployment and a free Heroku redis instance is added as add-on.

    .. image:: png/heroku.png

Environment variables set on Heroku control the bot behavior:

    .. image:: png/config_vars.png

When running on Heroku ngrok is not involved. Instead the public URL of the bot is based on the name of the application
on Heroku. The bot determines that it's running on Heroku by checking the ``HEROKU_NAME`` environment variable
(see above).

    .. image:: png/heroku_overview.png

* wxc_cc_bot: the actual bot.

* redis: The bot uses Redis to store state information for active authentication flows and user token information.

  On Heroku a free Redis instance is added as add-on to the application and environment variables are set to the
  connection parameters of the Redis add-on to enable the bot to establish a connection with Redis.
