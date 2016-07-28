'''Auto Op module for Willie IRC bot.'''
# Copyright 2015 Christopher Foo <chris.foo@gmail.com>. License GPLv3.

import contextlib
import datetime
import logging
import os
import re
import time
import random
import threading

from sqlalchemy import Column, String, DateTime, create_engine, delete, \
    insert, update, Enum, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.functions import count
from willie.config import ConfigurationError
import sqlalchemy.event
import willie.module
import willie.tools


__version__ = '1.5.4'
_logger = logging.getLogger(__name__)


PRIVILEGE_LEVELS = (willie.module.OP, willie.module.VOICE)

STR_TO_PRIV_MAP = {
    'v': willie.module.VOICE,
    'h': willie.module.HALFOP,
    'o': willie.module.OP,
    'a': willie.module.ADMIN,
    'q': willie.module.OWNER
}
PRIV_TO_STR_MAP = dict((value, key) for key, value in STR_TO_PRIV_MAP.items())

DBBase = declarative_base()


class AdminAuth(object):
    '''Authentication table.

    Keeps track of authenticated users sudo-style by expiring after a few
    minutes.
    '''
    def __init__(self, cache_time=300):
        self._cache_time = cache_time
        self._name_map = {}
        self._lock = threading.Lock()

    def add(self, name):
        '''Add an authenticated name to the table.'''
        _logger.info('Authenticated %s.', name)

        with self._lock:
            self._name_map[name] = datetime.datetime.utcnow()

    def remove(self, name):
        '''Remove an authenticated name.'''
        with self._lock:
            value = self._name_map.pop(name, None)

        if value:
            _logger.info('Remove authenticated %s.', name)

    def check(self, name):
        '''Return whether the name is not expired.'''
        with self._lock:
            if name in self._name_map:
                datetime_now = datetime.datetime.utcnow()
                auth_datetime = self._name_map[name]

                return datetime_now - auth_datetime <= \
                    datetime.timedelta(seconds=self._cache_time)
            else:
                return False

    def clean(self):
        '''Remove expired entries.'''
        _logger.debug('Clean authenticated.')
        datetime_now = datetime.datetime.utcnow()

        with self._lock:
            for name in tuple(self._name_map.keys()):
                auth_datetime = self._name_map.get(name)

                if auth_datetime:
                    if datetime_now - auth_datetime > \
                            datetime.timedelta(seconds=self._cache_time):
                        self._name_map.pop(name, None)


class PrivilegeRecord(DBBase):
    __tablename__ = 'privileges'

    channel = Column(String, primary_key=True, nullable=False)
    nickname = Column(String, primary_key=True, nullable=False)
    hostmask = Column(String, nullable=False)
    level = Column(Integer, nullable=False)
    when_privileged = Column(
        DateTime, default=datetime.datetime.utcnow, nullable=False
    )
    touch = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class Channel(DBBase):
    __tablename__ = 'channels'

    channel = Column(String, primary_key=True, nullable=False)


class BaseDatabase(object):
    def __init__(self, db_path):
        self._engine = create_engine('sqlite:///{0}'.format(db_path))
        sqlalchemy.event.listen(
            self._engine, 'connect', self._apply_pragmas_callback
        )
        DBBase.metadata.create_all(self._engine)
        self._session_maker_instance = sessionmaker(bind=self._engine)

    @classmethod
    def _apply_pragmas_callback(cls, connection, record):
        '''Set SQLite pragmas.'''
        connection.execute('PRAGMA synchronous=NORMAL')

    @property
    def _session_maker(self):
        return self._session_maker_instance

    @contextlib.contextmanager
    def _session(self):
        """Provide a transactional scope around a series of operations."""
        # Taken from the session docs.
        session = self._session_maker()
        try:
            yield session
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            session.close()


class PrivilegeTracker(BaseDatabase):
    '''Track ops and voices.'''
    def __init__(self, db_path, max_absent_time=86400, min_priv_time=300):
        super().__init__(db_path)
        self._max_absent_time = max_absent_time
        self._min_priv_time = min_priv_time
        self._lock = threading.Lock()

    def clean(self):
        '''Remove old entries.'''
        _logger.debug('Clean privileges.')
        time_ago = datetime.datetime.utcfromtimestamp(
            time.time() - self._max_absent_time
        )

        with self._lock, self._session() as session:
            query = delete(PrivilegeRecord)\
                .where(PrivilegeRecord.touch < time_ago)
            session.execute(query)

    def grant(self, channel, nickname, hostmask, level):
        '''Add privilege for user.'''
        self._try_insert(channel, nickname, hostmask, level)
        self._upgrade_level(channel, nickname, hostmask, level)

    def _try_insert(self, channel, nickname, hostmask, level):
        with self._lock, self._session() as session:
            before_num_rows = session.query(count(PrivilegeRecord.channel)) \
                .scalar()

            query = insert(PrivilegeRecord).prefix_with('OR IGNORE')
            session.execute(
                query,
                {
                    'channel': channel,
                    'nickname': nickname,
                    'hostmask': hostmask,
                    'level': level
                }
            )

            after_num_rows = session.query(count(PrivilegeRecord.channel)) \
                .scalar()

            if before_num_rows != after_num_rows:
                _logger.info(
                    'Grant privilege for channel=%s nickname=%s '
                    'hostmask=%s level=%s',
                    channel, nickname, hostmask, level
                )

    def _upgrade_level(self, channel, nickname, hostmask, level):
        with self._lock, self._session() as session:
            query = update(PrivilegeRecord) \
                .where(PrivilegeRecord.channel == channel) \
                .where(PrivilegeRecord.nickname == nickname) \
                .where(PrivilegeRecord.hostmask == hostmask) \
                .where(PrivilegeRecord.level < level)

            rows = session.execute(
                query,
                {
                    'level': level,
                }
            )

            if getattr(rows, 'rowcount'):
                _logger.info(
                    'Grant privilege for channel=%s nickname=%s '
                    'hostmask=%s level=%s',
                    channel, nickname, hostmask, level
                )

    def revoke(self, channel, nickname):
        '''Remove privilege for user.'''
        _logger.info(
            'Revoke privilege from channel=%s nickname=%s',
            channel, nickname
        )

        with self._lock, self._session() as session:
            query = delete(PrivilegeRecord) \
                .where(PrivilegeRecord.channel == channel)\
                .where(PrivilegeRecord.nickname == nickname)
            session.execute(query)

    def revoke_all(self, channel):
        '''Remove privileges for channel.'''
        _logger.info(
            'Revoke privilege from channel=%s',
            channel
        )

        with self._lock, self._session() as session:
            query = delete(PrivilegeRecord) \
                .where(PrivilegeRecord.channel == channel)
            session.execute(query)

    def touch(self, channel, nickname, hostmask, level):
        '''Update privilege for user.'''

        self._try_insert(channel, nickname, hostmask, level)
        self._upgrade_level(channel, nickname, hostmask, level)

        with self._lock, self._session() as session:
            query = update(PrivilegeRecord) \
                .where(PrivilegeRecord.channel == channel) \
                .where(PrivilegeRecord.nickname == nickname) \
                .where(PrivilegeRecord.hostmask == hostmask)

            session.execute(
                query,
                {
                    'touch': datetime.datetime.utcnow(),
                }
            )

    def get_privileged(self, channel, level):
        '''Return privileged list of nickname & hostmask pairs.'''
        with self._lock, self._session() as session:
            touch_ago = datetime.datetime.utcfromtimestamp(
                time.time() - self._max_absent_time
            )
            grant_ago = datetime.datetime.utcfromtimestamp(
                time.time() - self._min_priv_time
            )

            query = session.query(
                PrivilegeRecord.nickname,
                PrivilegeRecord.hostmask
                )\
                .filter_by(level=level, channel=channel)\
                .filter(PrivilegeRecord.touch > touch_ago)\
                .filter(PrivilegeRecord.when_privileged < grant_ago)

            for row in query:
                yield row.nickname, row.hostmask


class ChannelTracker(BaseDatabase):
    '''Track channels for auto join.'''

    MAX_OPLESS_TIME = 86400 * 2

    def __init__(self, db_path):
        super().__init__(db_path)
        self._lock = threading.Lock()
        self._op_time_table = {}

    def add(self, channel):
        with self._lock, self._session() as session:
            session.execute(
                insert(Channel).prefix_with('OR IGNORE'),
                {
                    'channel': channel
                }
            )

    def remove(self, channel):
        with self._lock, self._session() as session:
            session.execute(
                delete(Channel).where(Channel.channel == channel),
                {
                    'channel': channel
                }
            )

    def get_all(self):
        with self._lock, self._session() as session:
            query = session.query(Channel.channel)

            for row in query:
                yield row.channel

    def count(self):
        return len(tuple(self.get_all()))

    def touch_op(self, channel):
        self._op_time_table[channel] = time.time()

    def opless_time(self, channel):
        if channel not in self._op_time_table:
            # Bot has just started up. Give some time for people to op the bot.
            self._op_time_table[channel] = time.time()

        time_now = time.time()
        when_opped = self._op_time_table[channel]

        return time_now - when_opped


class HostmaskMap(dict):
    '''Track nicknames to hostmasks.'''
    def add(self, nickname, hostmask):
        _logger.debug('Map %s to %s', nickname, hostmask)

        self.clean()

        self[nickname] = hostmask

    def remove(self, nickname):
        _logger.debug('Unmap %s', nickname)

        self.pop(nickname, None)

    def clean(self):
        _logger.debug('Clean map')

        while len(self) > 1000:
            try:
                self.popitem()
            except KeyError:
                pass


_admin_auth = None
_priv_tracker = None
_hostmask_map = None
_channel_tracker = None


def configure(config):
    if not config.option('Configure PleaseOpMe'):
        return

    config.interactive_add(
        'pleaseopme', 'db_path',
        'PleaseOpMe: Database filename',
        default=os.path.abspath(os.path.expanduser('~/.willie/pleaseopme.db'))
    )
    config.interactive_add(
        'pleaseopme', 'admin_password',
        'PleaseOpMe: Admin password (leave blank to disable)', ispass=True
    )
    config.add_list(
        'pleaseopme', 'whitelist',
        'PleaseOpMe: Whitelisted channels (leave blank to allow all)', 'Channel'
    )
    config.add_option(
        'pleaseopme', 'logging', 'PleaseOpMe: Enable log output'
    )
    config.add_option(
        'pleaseopme', 'reply_help', 'PleaseOpMe: Reply to help command'
    )
    config.add_option(
        'pleaseopme', 'auto_join',
        'PleaseOpMe: Remember and auto join channels on start'
    )
    config.add_option(
        'pleaseopme', 'auto_part',
        'PleaseOpMe: Automatically part channels if not op for 2 days'
    )
    config.add_option(
        'pleaseopme', 'max_channels',
        'PleaseOpMe: Maximum number of channels'
    )


def setup(bot):
    global _admin_auth
    global _priv_tracker
    global _hostmask_map
    global _channel_tracker

    if not bot.config.pleaseopme.db_path:
        raise ConfigurationError('Option "db_path" is required.')

    if bot.config.pleaseopme.logging:
        logging.basicConfig(level=logging.INFO)

    _admin_auth = AdminAuth()
    _priv_tracker = PrivilegeTracker(bot.config.pleaseopme.db_path)
    _channel_tracker = ChannelTracker(bot.config.pleaseopme.db_path)
    _hostmask_map = HostmaskMap()


@willie.module.rate(10)
@willie.module.event('INVITE')
@willie.module.rule(r'.*')
def join_on_invite(bot, trigger):
    channel = trigger.args[1]
    whitelisted_channels = bot.config.pleaseopme.get_list('whitelist')
    try:
        max_channels = int(bot.config.pleaseopme.max_channels)
    except (TypeError, ValueError):
        max_channels = None

    if not whitelisted_channels or channel in whitelisted_channels:
        current_num_channels = _channel_tracker.count()
        if max_channels and current_num_channels >= max_channels:
            bot.reply('Too many channels.')
        else:
            _logger.info('Join channel %s by %s', channel, trigger.nick)
            bot.reply('Joining channel {0}'.format(channel))
            bot.join(channel)
            _channel_tracker.add(channel.lower())
    else:
        bot.reply('Channel is not whitelisted.')


def validate_channel_name(name):
    match = re.match(r'[&#+!][^ ,\x07]{1,50}$', name)

    if match:
        return name


@willie.module.require_privmsg()
@willie.module.rule('(help|commands|info)')
def reply_help(bot, trigger):
    if bot.config.pleaseopme.reply_help:
        bot.say("I'm Willie bot with PleaseOpMe module.")


@willie.module.rate(10)
@willie.module.require_privmsg()
@willie.module.rule(r'(auth)\s+(.*)')
def auth_as_admin(bot, trigger):
    password = trigger.match.group(2)

    if not bot.config.pleaseopme.admin_password:
        bot.say('Password not configured.')
    elif password == bot.config.pleaseopme.admin_password:
        _admin_auth.add(lower_hostmask(trigger.hostmask))
        bot.say('OK.')
    else:
        _admin_auth.remove(lower_hostmask(trigger.hostmask))
        bot.say('Invalid password.')


def check_is_admin(bot, trigger):
    if trigger.admin:
        return True

    if _admin_auth.check(lower_hostmask(trigger.hostmask)):
        return True


@willie.module.require_privmsg()
@willie.module.rule(r'(part)\s+(.*)')
def admin_part(bot, trigger):
    if not check_is_admin(bot, trigger):
        bot.say('Denied.')
        return

    channel = trigger.match.group(2)
    channel = validate_channel_name(channel)

    if not channel:
        bot.say('Huh? Is that a channel?')
        return

    _logger.info('Part channel %s by %s', channel, trigger.nick)
    bot.say('Parting channel {}'.format(channel))
    bot.part(channel)
    _channel_tracker.remove(channel.lower())


@willie.module.require_privmsg()
@willie.module.rule(r'channels')
def admin_channels(bot, trigger):
    if not check_is_admin(bot, trigger):
        bot.say('Denied.')
        return

    bot.say(' '.join(bot.privileges.keys()))


@willie.module.nickname_commands('op')
def manual_op(bot, trigger):
    if not check_is_admin(bot, trigger):
        bot.reply('Denied.')
        return

    channel = trigger.sender

    if bot.privileges[trigger.sender][bot.nick] < willie.module.OP:
        bot.reply("I don't have ops.")
        return

    _logger.info('Op %s %s', channel, trigger.nick)
    bot.write(['MODE', channel, '+o', trigger.nick])


@willie.module.nickname_commands('revokeall')
def manual_revoke_all(bot, trigger):
    channel = trigger.sender

    if bot.privileges[channel][trigger.nick] & willie.module.OP:
        _logger.info('Revoke all %s %s', channel, trigger.nick)
        _priv_tracker.revoke_all(channel.lower())
        bot.reply('OK.')
    else:
        bot.reply('Denied.')


@willie.module.rule(r'.*')
@willie.module.event('NICK')
@willie.module.priority('high')
@willie.module.unblockable
def rename_nick(bot, trigger):
    old = trigger.nick
    new = willie.tools.Identifier(trigger)

    _admin_auth.remove(old.lower())
    _admin_auth.remove(new.lower())
    _hostmask_map.remove(old.lower())
    _hostmask_map.remove(new.lower())


@willie.module.rule(r'.*')
@willie.module.event('QUIT')
@willie.module.priority('high')
@willie.module.unblockable
def remove_nick_quit(bot, trigger):
    _admin_auth.remove(trigger.nick.lower())
    _hostmask_map.remove(trigger.nick.lower())


@willie.module.rule(r'.*')
@willie.module.event('KICK')
@willie.module.priority('high')
@willie.module.unblockable
def track_kick(bot, trigger):
    nick = willie.tools.Identifier(trigger.args[1])

    _admin_auth.remove(nick.lower())
    _priv_tracker.revoke(trigger.sender.lower(), nick.lower())
    _hostmask_map.remove(nick.lower())
    _channel_tracker.remove(trigger.sender.lower())


@willie.module.rule(r'.*')
@willie.module.event('MODE')
@willie.module.priority('high')
@willie.module.unblockable
def channel_nick_mode_change(bot, trigger):
    # Logic mostly copied from willie/coretasks.py
    channel = willie.tools.Identifier(trigger.args[0])
    line = trigger.args[1:]

    if channel.is_nick():
        return

    modes = None
    nicks = []

    for arg in line:
        if not arg:
            continue

        if arg[0] in '+-':
            sign = ''
            modes = []

            for char in arg:
                if char == '+' or char == '-':
                    sign = char
                else:
                    modes.append((sign, char))

        elif modes:
            nick = willie.tools.Identifier(arg)
            nicks.append(nick)

    if len(modes) != len(nicks):
        return

    for index in range(len(modes)):
        sign, mode = modes[index]
        nick = nicks[index]

        if sign == '-':
            _priv_tracker.revoke(channel.lower(), nick.lower())
        elif sign == '+':
            priv_level = STR_TO_PRIV_MAP.get(mode)
            hostmask = _hostmask_map.get(nick.lower())

            if hostmask and priv_level in PRIVILEGE_LEVELS:
                _priv_tracker.grant(
                    channel.lower(), nick.lower(), hostmask, priv_level
                )


@willie.module.rule(r'.*')
@willie.module.event('JOIN', 'PRIVMSG', 'NOTICE', 'INVITE', 'MODE')
@willie.module.unblockable
def update_nick_hostmask(bot, trigger):
    if trigger.nick.is_nick():
        _hostmask_map.add(
            trigger.nick.lower(), lower_hostmask(trigger.hostmask)
        )


@willie.module.rule(r'.*')
@willie.module.event('311')
@willie.module.unblockable
def update_whois_hostmask(bot, trigger):
    nick, user, host = trigger.args[1:4]
    nick_identifer = willie.tools.Identifier(nick)

    hostmask = '{0}!{1}@{2}'.format(nick_identifer.lower(), user, host)
    _logger.debug('Add hostmask %s %s', nick, hostmask)
    _hostmask_map.add(nick_identifer.lower(), hostmask)


_nicks_pending_whois = set()
_last_pending_nicks_clear = time.time()

@willie.module.interval(13)
def whois_unknown(bot):
    global _last_pending_nicks_clear

    if time.time() - _last_pending_nicks_clear > 301:
        _last_pending_nicks_clear = time.time()
        _nicks_pending_whois.clear()

    channels = list(bot.privileges.keys())
    random.shuffle(channels)

    for channel in channels:
        nicks = list(bot.privileges[channel].keys())
        random.shuffle(nicks)

        for nick in nicks:
            nick_lowered = nick.lower()
            if not _hostmask_map.get(nick_lowered) and \
                    nick_lowered not in _nicks_pending_whois:
                _nicks_pending_whois.add(nick_lowered)
                bot.write(('WHOIS', nick))
                return


@willie.module.interval(63)
def touch_privilege(bot):
    _priv_tracker.clean()

    # The bot library is a mess when it comes to threading :P
    for channel in list(bot.privileges.keys()):
        if channel not in bot.privileges:
            continue

        for nick in list(bot.privileges[channel].keys()):
            try:
                priv_flags = bot.privileges[channel][nick]
            except KeyError:
                continue

            hostmask = _hostmask_map.get(nick)

            if not hostmask:
                continue

            for priv_level in PRIVILEGE_LEVELS:
                if priv_level & priv_flags:
                    _priv_tracker.touch(
                        channel.lower(), nick.lower(), hostmask, priv_level
                    )
                    continue


_auto_join_lock = threading.Lock()

@willie.module.event('001', '251')
@willie.module.interval(7201)
@willie.module.rule(r'.*')
@willie.module.unblockable
def auto_join(bot, trigger=None):
    if not bot.config.pleaseopme.auto_join:
        return

    whitelisted_channels = bot.config.pleaseopme.get_list('whitelist')

    for channel in _channel_tracker.get_all():
        if not whitelisted_channels or channel in whitelisted_channels:
            with _auto_join_lock:
                if channel in bot.privileges:
                    continue

                _logger.info('Auto join %s', channel)
                bot.join(channel)
                time.sleep(5)


@willie.module.interval(61)
def auto_priv(bot):
    def check_and_change_channel(channel):
        for level in PRIVILEGE_LEVELS:
            tracked = tuple(_priv_tracker.get_privileged(channel, level))

            _logger.debug('%s', tracked)

            for nick, tracked_hostmask in tracked:
                if nick not in bot.privileges[channel]:
                    continue

                current_nick_priv_flags = bot.privileges[channel][nick]
                mode = PRIV_TO_STR_MAP.get(level)
                current_nick_hostmask = _hostmask_map.get(nick.lower())

                _logger.debug(
                    'Checking channel=%s nick=%s hostmask=%s '
                    'flags=%s candidate=%s',
                    channel, nick, current_nick_hostmask,
                    current_nick_priv_flags, mode
                )

                if not current_nick_priv_flags & level and mode \
                        and current_nick_hostmask == tracked_hostmask:
                    _logger.info('Auto mode %s %s %s', channel, nick, mode)
                    bot.write(['MODE', channel, '+{0}'.format(mode), nick])
                    time.sleep(1)
                    return  # change modes slowly one at a time

    for channel in bot.privileges:
        # Threading issues :P
        try:
            priv_level = bot.privileges[channel][bot.nick]
        except KeyError:
            continue

        if priv_level < willie.module.OP:
            _logger.debug('Not op in %s', channel)
        else:
            check_and_change_channel(channel)


@willie.module.interval(3013)
def auto_part(bot):
    if not bot.config.pleaseopme.auto_part:
        return

    for channel in list(bot.privileges.keys()):
        # Threading issues :P
        try:
            priv_level = bot.privileges[channel][bot.nick]
        except KeyError:
            continue

        channel = channel.lower()

        if priv_level & willie.module.OP:
            _channel_tracker.touch_op(channel)
        elif _channel_tracker.opless_time(channel) > ChannelTracker.MAX_OPLESS_TIME:
            _logger.info('Auto part %s', channel)
            bot.part(channel)
            _channel_tracker.remove(channel)
            time.sleep(2)


def lower_hostmask(hostmask):
    if '!' in hostmask:
        nick, rest = hostmask.split('!', 1)
        nick_identifer = willie.tools.Identifier(nick)

        hostmask = '{0}!{1}'.format(nick_identifer.lower(), rest)
        return hostmask
    else:
        return hostmask
