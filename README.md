# Play with the Wexex Calling Call Control APIs

Bot as test environment. 

Required parameters for Bot need to be defined in .env.

Bot uses ngrok to be able to use Webhooks w/o public firewall. When running directly then ngrok needs to be installed
locally and an ngork process is started as required.

To avoid installing ngrok locally instead the bot can run in Docker. To start the bot use: `docker-compose up`.

The required Docker images are then built/downloaded before starting a bot container and an ngrok container.