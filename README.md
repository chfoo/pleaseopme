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

Add our the PleaseOpMe module by copying or symlinking `pleaseopme.py` into the `~/.willie/modules/` (or wherever the configuration is located).

To use only PleaseOpMe and disable all other Willie features, add `enable = pleaseopme` under `[core]` in the `default.cfg` file.

Rerun the configuration wizard to answer the PleaseOpMe settings.


Usage
=====

To get the bot to join a channel, use the `/invite` command.

The bot will monitor active users with operator (@) or voice (+) and give them back when they rejoin if they fit the criteria. The user must 

* have the same hostmask (same nick, user, and host), 
* have said (or `/me`) something so the bot knows the user's hostmask, 
* have op or voice for at least 60 seconds, 
* and be back in the channel within 24 hours.

Password authentication is done by sending a private message with `auth PASSWORD`. The password is cached for 5 minutes.

To force the bot to leave, `/kick` the bot. Alternatively, send a private message to the bot with `part CHANNEL_NAME`.

If you are bot admin, message the bot (say `BOT_NAME: op`) in the channel to get ops.

Channel operators can message the bot `revokeall` (say `BOT_NAME: revokeall`) in the channel to force it to clear its privilege table.

