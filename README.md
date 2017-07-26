# PleaseOpMe
Auto Op bot for IRC.

Inspired by EFnet's CHANFIX, this bot attempts to keep operator or voice mode to users in the channel.


Install
=======

Requires:

* Python 3+
* IRC module 16.0
* SQLAlchemy module

Install Python, then use pip to install the Python libraries:

        pip3 install --user irc sqlalchemy

Then, set up the bot by editing the sample configuration file and run it:

        python3 pleaseopme.py my_config_file.ini

Note: This script was formerly a Willie Bot module. It is now a standalone script for stability reasons. You may still use the older versions by navigating to the older branch in the Git repository. 


Usage
=====

To get the bot to join a channel, use the `/invite` command.

The bot will monitor active users with operator (@) or voice (+) and give them back when they rejoin if they fit the criteria. The user must 

* have the same hostmask (same nick, user, and host),
* have said (or `/me`) something so the bot knows the user's hostmask if the bot has not done a WHOIS/WHO query on the user yet,
* have op or voice for at least 60 seconds,
* and be back in the channel within 24 hours.


Channel operators
-----------------

To force the bot to leave, `/kick` the bot. 

To force it to clear its privilege table for the current channel, message the bot `revokeall` (say `BOT_NAME: revokeall`).


Bot admin
---------

Password authentication is done by sending a private message with `auth PASSWORD`. The password is cached for 5 minutes.

To force the bot to leave a channel, send a private message to the bot with `part CHANNEL_NAME`.

To get ops, message the bot `op` (say `BOT_NAME: op`) in the channel. 

To get a list of currently joined channels, send a private message `channels` .


Tips
====

* The bot may occasionally need to be restarted due to bugs or updates. Run at least two bots with each on different servers and connected to a different IRC server.
* Start the bot with a daemon system such as Upstart or Systemd and configure it to restart if the bot dies (with appropriate restart intervals if applicable).
* If the daemon system supports delays, include a delay of about 45 to 60 seconds to avoid flooding the server. Otherwise, use the sleep command as part of the start up script.
