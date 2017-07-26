"""PleaseOpMe: Auto Op bot for IRC."""
# Copyright 2015-2017 Christopher Foo <chris.foo@gmail.com>. License GPLv3.
import configparser
import contextlib
import datetime
import enum
import logging
import re
import ssl
import time
import threading
import argparse
import functools

from sqlalchemy import Column, String, DateTime, create_engine, delete, \
    insert, update, Enum, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.functions import count
import sqlalchemy.event
import irc.bot
import irc.client
import irc.strings
from irc.client import ServerConnection, Event
import irc.connection
import irc.modes


__version__ = '2.0.0'
_logger = logging.getLogger(__name__)


class PrivilegeLevel(enum.IntEnum):
    VOICE = 1
    HALFOP = 2
    OP = 4
    ADMIN = 8
    OWNER = 16


MONITORED_PRIVILEGE_LEVELS = (PrivilegeLevel.OP, PrivilegeLevel.VOICE)

STR_TO_PRIV_MAP = {
    'v': PrivilegeLevel.VOICE,
    'h': PrivilegeLevel.HALFOP,
    'o': PrivilegeLevel.OP,
    'a': PrivilegeLevel.ADMIN,
    'q': PrivilegeLevel.OWNER
}
PRIV_TO_STR_MAP = dict((value, key) for key, value in STR_TO_PRIV_MAP.items())

DBBase = declarative_base()


class AdminAuth(object):
    """Authentication table.

    Keeps track of authenticated users sudo-style by expiring after a few
    minutes.
    """
    def __init__(self, cache_time=300):
        self._cache_time = cache_time
        self._name_map = {}
        self._lock = threading.Lock()

    def add(self, name):
        """Add an authenticated name to the table."""
        _logger.info('Authenticated %s.', name)

        with self._lock:
            self._name_map[name] = datetime.datetime.utcnow()

    def remove(self, name):
        """Remove an authenticated name."""
        with self._lock:
            value = self._name_map.pop(name, None)

        if value:
            _logger.info('Remove authenticated %s.', name)

    def check(self, name):
        """Return whether the name is not expired."""
        with self._lock:
            if name in self._name_map:
                datetime_now = datetime.datetime.utcnow()
                auth_datetime = self._name_map[name]

                return datetime_now - auth_datetime <= \
                    datetime.timedelta(seconds=self._cache_time)
            else:
                return False

    def clean(self):
        """Remove expired entries."""
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
        """Set SQLite pragmas."""
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
    """Track ops and voices."""
    def __init__(self, db_path, max_absent_time=86400, min_priv_time=300):
        super().__init__(db_path)
        self._max_absent_time = max_absent_time
        self._min_priv_time = min_priv_time
        self._lock = threading.Lock()

    def clean(self):
        """Remove old entries."""
        _logger.debug('Clean privileges.')
        time_ago = datetime.datetime.utcfromtimestamp(
            time.time() - self._max_absent_time
        )

        with self._lock, self._session() as session:
            query = delete(PrivilegeRecord)\
                .where(PrivilegeRecord.touch < time_ago)
            session.execute(query)

    def grant(self, channel, nickname, hostmask, level):
        """Add privilege for user."""
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
                    'Grant privilege (new) for channel=%s nickname=%s '
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
                    'Grant privilege (upgrade) for channel=%s nickname=%s '
                    'hostmask=%s level=%s',
                    channel, nickname, hostmask, level
                )

    def revoke(self, channel, nickname):
        """Remove privilege for user."""
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
        """Remove privileges for channel."""
        _logger.info(
            'Revoke privilege from channel=%s',
            channel
        )

        with self._lock, self._session() as session:
            query = delete(PrivilegeRecord) \
                .where(PrivilegeRecord.channel == channel)
            session.execute(query)

    def touch(self, channel, nickname, hostmask, level):
        """Update privilege for user."""

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
        """Return privileged list of nickname & hostmask pairs."""
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
    """Track channels for auto join."""

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
    """Track nicknames to hostmasks."""
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


class Bot(irc.bot.SingleServerIRCBot):
    def __init__(self, config: configparser.ConfigParser):
        server = config['irc']['server']
        port = config['irc'].getint('port')
        use_ssl = config['irc'].getboolean('use_ssl')
        nickname = config['irc']['nickname']
        realname = config['irc']['realname']

        if use_ssl:
            connect_factory = irc.connection.Factory(wrapper=ssl.wrap_socket)
        else:
            connect_factory = irc.connection.Factory()

        super().__init__(
            [(server, port)],
            nickname, realname,
            connect_factory=connect_factory
        )

        self._config = config
        self._admin_auth = AdminAuth()
        self._priv_tracker = PrivilegeTracker(config['pleaseopme']['db_path'])
        self._channel_tracker = ChannelTracker(config['pleaseopme']['db_path'])
        self._hostmask_map = HostmaskMap()

        self.connection.set_rate_limit(0.5)

        self.reactor.scheduler.execute_every(62, self._touch_privilege)
        self.reactor.scheduler.execute_every(7201, self._auto_join_channels)
        self.reactor.scheduler.execute_every(61, self._auto_priv)
        self.reactor.scheduler.execute_every(3013, self._auto_part)

    def get_version(self):
        # Remove bot from string in case server does not like bots ;)
        return 'PleaseOpMe ({}) {}'.format(
            __version__,
            super().get_version().replace('.bot', '')
        )

    def on_invite(self, connection: ServerConnection, event: Event):
        if not isinstance(event.source, irc.client.NickMask):
            return

        nick = event.source.nick
        channel = event.arguments[0]

        _logger.info('Received invite from %s to %s', nick, channel)

        whitelisted_channels = split_list_option(self._config['pleaseopme']['whitelist'])
        max_channels = self._config['pleaseopme'].getint('max_channels', None)

        if not whitelisted_channels or channel in whitelisted_channels:
            current_num_channels = self._channel_tracker.count()
            if max_channels and current_num_channels >= max_channels:
                connection.privmsg(nick, 'Too many channels.')
            else:
                _logger.info('Join channel %s by %s', channel, nick)
                connection.privmsg(nick, 'Joining channel {0}'.format(channel))
                connection.join(channel)
                connection.who(channel)
                self._channel_tracker.add(irc.strings.lower(channel))
        else:
            connection.privmsg(nick, 'Channel is not whitelisted.')

    @classmethod
    def validate_channel_name(cls, name) -> bool:
        match = re.match(r'[&#+!][^ ,\x07]{1,50}$', name)

        return bool(match)

    def on_privmsg(self, connection: ServerConnection, event: Event):
        if not isinstance(event.source, irc.client.NickMask):
            return

        nick = irc.strings.lower(event.source.nick)
        text = event.arguments[0]
        hostmask = self.lower_hostmask(event.source)

        def reply(message: str):
            connection.privmsg(nick, message)

        if re.match(r'help|commands|info', text):
            if self._config['pleaseopme'].getboolean('reply_help'):
                help_text = self._config['pleaseopme']['help_text']
                reply(help_text)

        elif re.match(r'auth\s(.+)', text):
            match = re.match(r'auth\s(.+)', text)
            password = match.group(1)
            admin_password = self._config['pleaseopme']['admin_password']

            if not admin_password:
                reply('Password not configured.')
            elif password == admin_password:
                self._admin_auth.add(hostmask)
                reply('OK.')
            else:
                self._admin_auth.remove(hostmask)
                reply('Invalid password.')

        elif re.match(r'part\s+(.*)', text):
            if not self.check_is_admin(hostmask):
                reply('Unauthorized.')
                return

            match = re.match(r'part\s+(.*)', text)
            channel = irc.strings.lower(match.group(1))

            if not self.validate_channel_name(channel):
                reply('Huh? Is that a channel?')
                return

            _logger.info('Part channel %s by %s', channel, nick)
            reply('Parting channel {}'.format(channel))
            connection.part(channel)
            self._channel_tracker.remove(channel.lower())

        elif text == "channels":
            if not self.check_is_admin(hostmask):
                reply('Unauthorized.')
                return

            reply(' '.join(self.channels.keys()))

    def check_is_admin(self, hostmask: str) -> bool:
        if self._admin_auth.check(hostmask):
            return True

    def on_pubmsg(self, connection: ServerConnection, event: Event):
        if not isinstance(event.source, irc.client.NickMask):
            return

        if not irc.client.is_channel(event.target):
            return

        self._update_nick_hostmask(event)

        nick = irc.strings.lower(event.source.nick)
        text = event.arguments[0]
        channel = irc.strings.lower(event.target)
        hostmask = self.lower_hostmask(event.source)

        def reply(message: str):
            connection.privmsg(channel, '{}: {}'.format(nick, message))

        command = None
        match = re.match(
            r'{}[:,]\s(\S+)'.format(re.escape(connection.get_nickname())),
            text
        )

        if match:
            command = match.group(1)

        if command == 'op':
            if not self.check_is_admin(hostmask):
                reply('Unauthorized.')
                return

            if not self.channels[channel].is_oper(connection.get_nickname()):
                reply("I don't have ops.")
                return

            _logger.info('Op %s %s', channel, nick)
            connection.mode(channel, '+o {}'.format(nick))

        elif command == "revokeall":
            if self.channels[channel].is_oper(connection.get_nickname()):
                _logger.info('Revoke all %s %s', channel, nick)
                self._priv_tracker.revoke_all(channel.lower())
                reply('OK.')
            else:
                reply('Unauthorized.')

    def on_nick(self, connection: ServerConnection, event: Event):
        old = irc.strings.lower(event.source.nick)
        new = irc.strings.lower(event.target)

        _logger.debug('nick %s->%s', old, new)

        self._admin_auth.remove(old)
        self._admin_auth.remove(new)
        self._hostmask_map.remove(old)
        self._hostmask_map.remove(new)

    def on_quit(self, connection: ServerConnection, event: Event):
        nick = irc.strings.lower(event.source.nick)

        _logger.debug('quit %s', nick)

        self._admin_auth.remove(nick)
        self._hostmask_map.remove(nick)

    def on_kick(self, connection: ServerConnection, event: Event):
        channel = irc.strings.lower(event.target)
        nick = irc.strings.lower(event.arguments[0])

        _logger.debug('kicked %s from %s', nick, channel)

        self._admin_auth.remove(nick)
        self._priv_tracker.revoke(channel, nick)
        self._hostmask_map.remove(nick)
        self._channel_tracker.remove(channel)

    def on_mode(self, connection: ServerConnection, event: Event):
        # copied from irc.bot
        modes = irc.modes.parse_channel_modes(" ".join(event.arguments))
        target = irc.strings.lower(event.target)
        if irc.client.is_channel(target):
            channel = self.channels[target]
            for mode in modes:
                nick = irc.strings.lower(mode[2])
                if mode[0] == "+":
                    pass
                else:
                    self._priv_tracker.revoke(target, nick)

    def on_join(self, connection: ServerConnection, event: Event):
        self._update_nick_hostmask(event)

    def _update_nick_hostmask(self, event: Event):
        if not isinstance(event.source, irc.client.NickMask):
            return

        hostmask = self.lower_hostmask(event.source)

        _logger.debug('Update hostmask %s', hostmask)

        self._hostmask_map.add(
            hostmask.nick, hostmask
        )

    def on_whoisuser(self, connection: ServerConnection, event: Event):
        nick, user, host = event.arguments
        nick = irc.strings.lower(nick)
        hostmask = '{0}!{1}@{2}'.format(nick, user, host)

        _logger.debug('Add hostmask %s %s', nick, hostmask)
        self._hostmask_map.add(nick, hostmask)

    def on_whoreply(self, connection: ServerConnection, event: Event):
        channel, user, host, server, nick, *others = event.arguments
        nick = irc.strings.lower(nick)
        hostmask = '{0}!{1}@{2}'.format(nick, user, host)

        _logger.debug('Add hostmask %s %s', nick, hostmask)
        self._hostmask_map.add(nick, hostmask)

    def _touch_privilege(self):
        self._priv_tracker.clean()

        if not self.connection.is_connected():
            return

        for channel in self.channels.keys():
            for nick in self.channels[channel].users():
                priv_flags = self.populate_user_priv_flags(self.channels[channel], nick)
                nick = irc.strings.lower(nick)
                hostmask = self._hostmask_map.get(nick)

                if not hostmask:
                    continue

                for priv_level in MONITORED_PRIVILEGE_LEVELS:
                    if priv_level & priv_flags:
                        self._priv_tracker.touch(
                            channel.lower(), nick.lower(), hostmask, priv_level
                        )
                        continue

    @classmethod
    def populate_user_priv_flags(cls, channel: irc.bot.Channel, nick: str) -> int:
        priv_flags = 0

        if channel.is_oper(nick):
            priv_flags |= PrivilegeLevel.OP

        if channel.is_voiced(nick):
            priv_flags |= PrivilegeLevel.VOICE

        return priv_flags

    def on_welcome(self, connection: ServerConnection, event: Event):
        _logger.info('Logged into server')
        self._auto_join_channels()

    def on_disconnect(self, connection: ServerConnection, event: Event):
        _logger.info('Disconnected!')

    def _auto_join_channels(self):
        if not self._config['pleaseopme'].getboolean('auto_join', False):
            return

        if not self.connection.is_connected():
            return

        whitelisted_channels = split_list_option(self._config['pleaseopme']['whitelist'])

        pending_channels = []

        for channel in self._channel_tracker.get_all():
            if not whitelisted_channels or channel in whitelisted_channels:
                if channel in self.channels:
                    continue
                pending_channels.append(channel)

        while pending_channels:
            channel_group = []

            for dummy in range(10):
                if pending_channels:
                    channel_group.append(pending_channels.pop())

            group_str = ','.join(channel_group)
            _logger.info('Auto join %s', group_str)
            self.connection.join(group_str)

            for channel in channel_group:
                # Avoid blocking
                self.reactor.scheduler.execute_after(1, functools.partial(self.connection.who, channel))

    def _auto_priv(self):
        def check_and_change_channel(channel: str):
            for level in MONITORED_PRIVILEGE_LEVELS:
                tracked = tuple(self._priv_tracker.get_privileged(channel, level))

                _logger.debug('Tracked %s', tracked)

                for nick, tracked_hostmask in tracked:
                    if not self.channels[channel].has_user(nick):
                        continue

                    nick = irc.strings.lower(nick)

                    current_nick_priv_flags = self.populate_user_priv_flags(self.channels[channel], nick)
                    mode = PRIV_TO_STR_MAP.get(level)
                    current_nick_hostmask = self._hostmask_map.get(nick)

                    _logger.debug(
                        'Checking channel=%s nick=%s hostmask=%s '
                        'flags=%s candidate=%s',
                        channel, nick, current_nick_hostmask,
                        current_nick_priv_flags, mode
                    )

                    if not current_nick_priv_flags & level and mode \
                            and current_nick_hostmask == tracked_hostmask:
                        _logger.info('Auto mode %s %s %s', channel, nick, mode)
                        self.connection.mode(channel, '+{} {}'.format(mode, nick))
                        return  # change modes slowly one at a time

        for channel in self.channels.keys():
            if not self.channels[channel].is_oper(self.connection.get_nickname()):
                _logger.debug('Not op in %s', channel)
            else:
                _logger.debug('Checking for auto priv in %s', channel)
                check_and_change_channel(channel)

    def _auto_part(self):
        if not self._config['pleaseopme'].getboolean('auto_part'):
            return

        if not self.connection.is_connected():
            return

        for channel in self.channels.keys():
            channel = irc.strings.lower(channel)

            if self.channels[channel].is_oper(self.connection.get_nickname()):
                self._channel_tracker.touch_op(channel)
            elif self._channel_tracker.opless_time(channel) > ChannelTracker.MAX_OPLESS_TIME:
                _logger.info('Auto part %s', channel)
                self.connection.part(channel)
                self._channel_tracker.remove(channel)

    @classmethod
    def lower_hostmask(cls, hostmask: str) -> irc.client.NickMask:
        if '!' in hostmask:
            nick, rest = hostmask.split('!', 1)

            hostmask = '{0}!{1}'.format(irc.strings.lower(nick), rest)
            return irc.client.NickMask(hostmask)
        else:
            return irc.client.NickMask(hostmask)


def split_list_option(option: str) -> list:
    if option:
        return option.split(',')
    else:
        return []


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('config', help='Filename of config file')
    args = arg_parser.parse_args()

    config = configparser.ConfigParser()
    config.read([args.config])

    if config['pleaseopme'].getboolean("logging"):
        if config['pleaseopme'].getboolean("debug"):
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

    bot = Bot(config)
    bot.start()

if __name__ == '__main__':
    main()
