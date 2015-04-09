# PleaseOpMe
Auto Op module for Willie IRC bot.

Inspired by EFnet's CHANFIX, this module attempts to keep operator or voice mode to users in the channel.


Install
=======

Requires:

* Python 3+
* Willie 5
* SQLAlchemy

Install Python, then use pip to install the Python libraries:

        pip3 install --user willie sqlalchemy

Set up Willie by running:

        ~/.local/bin/willie --configure-all

Since an op bot should not be using extra features, just answer no to configuring the built-in Willie bot modules. `owner` and `admin` settings should use IRC hostmasks instead of just nicknames. (You can also leave them blank and use PleaseOpMe's password-based authentication.)

Add the PleaseOpMe module by copying or symlinking `pleaseopme.py` into the `~/.willie/modules/` (or wherever the configuration is located).

To use only PleaseOpMe and disable all other Willie features, add `enable = pleaseopme` under `[core]` in the `default.cfg` file.

Rerun the configuration wizard and say yes to configure the modules to answer the PleaseOpMe settings.


Usage
=====

To get the bot to join a channel, use the `/invite` command.

The bot will monitor active users with operator (@) or voice (+) and give them back when they rejoin if they fit the criteria. The user must 

* have the same hostmask (same nick, user, and host),
* have said (or `/me`) something so the bot knows the user's hostmask if the bot has not done a WHOIS query on the user yet,
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
* If the daemon system supports restarting, use the `exit_on_error` config option so the bot is freshly started on a new process to avoid any lingering bugs.
