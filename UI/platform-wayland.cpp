#include "platform.hpp"

#include <QString>
#include <QDBusMessage>
#include <QDBusConnection>
#include <QDBusReply>
#include <QDBusMetaType>
#include <QDBusPendingCallWatcher>
#include <QCoreApplication>
#include <QKeySequence>

#include <obs.h>
#include <util/dstr.hpp>

#include <xkbcommon/xkbcommon.h>

using namespace Qt::StringLiterals;

using shortcut = std::pair<QString, QVariantMap>;


static QString portalName()
{
	return u"org.freedesktop.portal.Desktop"_s;
}

static QString portalPath()
{
	return u"/org/freedesktop/portal/desktop"_s;
}

static QString globalShortcutsInterface()
{
	return u"org.freedesktop.portal.GlobalShortcuts"_s;
}

static QString getNextToken()
{
	static int tokens = 0;
	return u"obs%1"_s.arg(tokens++);
}


static QString buildShortcutId(obs_hotkey_t *hotkey)
{
	// This is NOT unique
	auto id = QString::fromUtf8(obs_hotkey_get_name(hotkey));
	// This is just a random int
	id += QString::number(obs_hotkey_get_id(hotkey));
	// TODO david find something better;
	return id;
}

static obs_hotkey_t *findHotkeyByPortalId(const QString &id)
{

	struct {
		const QString &id;
		obs_hotkey_t *result;
	} finder {.id = id, .result = nullptr};
	obs_enum_hotkeys([](void *data, size_t, obs_hotkey_t *hotkey) {
		auto f = static_cast<decltype(finder)*>(data);
		if (buildShortcutId(hotkey) == f->id) {
			f->result = hotkey;
				return false;
			}
			return true;
		}, &finder);
	return finder.result;
}


static obs_key_combination_t tryGuessKeyCombination(const QString &triggerDescription)
{
	if (triggerDescription.isEmpty()) {
		return obs_key_combination_t();
	}
	auto parts = triggerDescription.split('+', Qt::SkipEmptyParts);;
	auto guessKey = [](const QString &key) {
		qDebug() << "key" << key;
		obs_key_t obsKey = OBS_KEY_NONE;
		if (auto sym = xkb_keysym_from_name(key.toUtf8(), XKB_KEYSYM_CASE_INSENSITIVE); sym != XKB_KEY_NoSymbol) {
			obsKey = obs_key_from_virtual_key(sym);
			qCritical() << "found sym xkb_keysym_from_name" << sym << "obsKey" << obsKey;
		} else if (sym = xkb_utf32_to_keysym(key.toUcs4()[0]); key.size() == 1 && sym != XKB_KEY_NoSymbol) {
			obsKey = obs_key_from_virtual_key(sym);
			qCritical() << "found sym xkb_utf32_to_keysym" << sym << "obsKey" << obsKey;
		} else if (obsKey = obs_key_from_name(key.toUtf8()); obsKey != OBS_KEY_NONE) {
			qCritical() << "found obs key" << obsKey;
		} else {
			DStr str;
			for(int i = OBS_KEY_NONE; i < OBS_KEY_LAST_VALUE; i++) {
				obs_key_to_str((obs_key_t)i, str);
				if (key.toUtf8().compare(static_cast<const char*>(str), Qt::CaseInsensitive)) {
					obsKey = static_cast<obs_key>(i);
					break;
					qCritical() << "Found obs translation" << str.operator char *() << obsKey;
				}
			}
		}
		// TODO we can try Qt, but how to convert qt key to obs key
		return obsKey;
	};
	auto key = parts.takeLast();
	obs_key_t obsKey = guessKey(key);
	if (obsKey  == OBS_KEY_NONE) {
		return obs_key_combination();
	}
	const std::array modifierTable = {
		std::make_tuple(INTERACT_SHIFT_KEY, Qt::Key_Shift, "SHIFT"),
		std::make_tuple(INTERACT_CONTROL_KEY, Qt::Key_Control, "CTRL"),
		std::make_tuple(INTERACT_ALT_KEY, Qt::Key_Alt, "ALT"),
		std::make_tuple(INTERACT_COMMAND_KEY, Qt::Key_Meta, "LOGO"),

	};
	for (const auto& modifier : parts) {

	}
	return obs_key_combination();
}

class Request : public QObject  {
	Q_OBJECT
public:
	template <typename F>
	Request(const QDBusMessage &message, const QString &handleToken, F&& slot)
	{
		connect(this, &Request::response, [this, &slot] (uint response, const QVariantMap &results) {
			std::invoke(slot, response, results, this);
		});
		const QString path = u"/org/freedesktop/portal/desktop/request/%1/%2"_s.arg(QDBusConnection::sessionBus().baseService().replace('.', '_').mid(1)).arg(handleToken);
		QDBusConnection::sessionBus().connect(portalName(), path, u"org.freedesktop.portal.Request"_s, u"Response"_s, this, SIGNAL(response(uint, QVariantMap)));
		auto call = QDBusConnection::sessionBus().asyncCall(message);
		connect(new QDBusPendingCallWatcher(call, this), &QDBusPendingCallWatcher::finished, this, [this, message, path](QDBusPendingCallWatcher *watcher) {
			if (watcher->isError()) {
				qWarning() << "Error calling" << message.member() << watcher->error();
			}
		});

	}

	Q_SIGNAL void response(uint response, const QVariantMap &results);
};


class ShortcutsSession : public QObject {
	Q_OBJECT
public:
	ShortcutsSession(const QString &handle, QObject *parent) : QObject(parent), handle(handle)
	{
		bindAllShortcuts(handle);
		QDBusConnection::sessionBus().connect(portalName(), portalPath(), globalShortcutsInterface(), u"Activated"_s, this, SLOT(onShortcutActivated(QDBusObjectPath, QString, quint64, QVariantMap)));
		QDBusConnection::sessionBus().connect(portalName(), portalPath(), globalShortcutsInterface(), u"Deactivated"_s, this, SLOT(onShortcutDeactivated(QDBusObjectPath, QString, quint64, QVariantMap)));
		QDBusConnection::sessionBus().connect(portalName(), portalPath(), globalShortcutsInterface(), u"ShortcutsChanged"_s, this, SLOT(onShortcutsChanges(QDBusObjectPath, QVariantMap)));
	}
	~ShortcutsSession()
	{
		auto close = QDBusMessage::createMethodCall(portalName(), handle, u"org.freedesktop.portal.Session"_s, "Close");
		QDBusConnection::sessionBus().send(close);
	}
private Q_SLOTS:
	void onShortcutActivated(const QDBusObjectPath &sessionHandle, QString shortcutId, quint64 /*timestamp*/, const QVariantMap &)
	{
		if (sessionHandle.path() != handle) {
			return;
		}
		qWarning() << "shortcut activated" << shortcutId;
		if (auto hotkey = findHotkeyByPortalId(shortcutId)) {
			obs_hotkey_inject_hotkey_event(hotkey, true);
		}
	}
	void onShortcutDeactivated(const QDBusObjectPath &sessionHandle, QString shortcutId, quint64 /*timestamp*/, const QVariantMap &)
	{
		if (sessionHandle.path() != handle) {
			return;
		}
		qWarning() << "shortcut deactivated" << shortcutId;
		if (auto hotkey = findHotkeyByPortalId(shortcutId)) {
			obs_hotkey_inject_hotkey_event(hotkey, false);
		}
	}
private:
	void bindAllShortcuts(const QString &sessionHandle)
	{
		QList<shortcut> shortcuts;

		obs_enum_hotkeys([](void *data, size_t, obs_hotkey_t *hotkey) {
			auto s = static_cast<decltype(shortcuts)*>(data);
			qDebug() << obs_hotkey_get_name(hotkey) << obs_hotkey_get_registerer_type(hotkey);
			// TODO david these are not unique, find something that seems more stable than incremented int
			s->push_back({buildShortcutId(hotkey), {
				{u"description"_s, QString::fromUtf8(obs_hotkey_get_description(hotkey))},
				// {u"preferred_trigger_s", QString()}, TODO david
				}});
			return true;
		}, &shortcuts);

		const auto handleToken = getNextToken();
		auto bindShortcuts = QDBusMessage::createMethodCall(portalName(), portalPath(), globalShortcutsInterface(), u"BindShortcuts"_s);
		bindShortcuts << QDBusObjectPath(sessionHandle);
		bindShortcuts << QVariant::fromValue(shortcuts);
		bindShortcuts << QString(); // TODO david parent_window
		bindShortcuts << QVariantMap{{u"handle_token"_s, handleToken}};
		new Request(bindShortcuts, handleToken,  [](uint response, const QVariantMap &results, Request *request){
			delete request;
			QList<shortcut> shortcuts;
			results.value(u"shortcuts"_s).value<QDBusArgument>() >> shortcuts;
			qWarning() << "bind all shortcuts" << response;
			// TODO david this does not really work
			for (const auto &shortcut : shortcuts) {
				const QString triggerDescription = shortcut.second.value(u"trigger_description"_s).toString();
				std::vector<obs_key_combination_t> combinations;
				for (const auto &part : triggerDescription.split(',', Qt::SkipEmptyParts)) {
					obs_key_combination_t obs_key_combination = tryGuessKeyCombination(part);
					combinations.push_back(obs_key_combination);
				}
				if (auto hotkey = findHotkeyByPortalId(shortcut.first)) {
					obs_hotkey_load_bindings(obs_hotkey_get_id(hotkey), combinations.data(), combinations.size());
				}
			}
		});
	}
	const QString handle;
};

void setupGlobalShortcutsPortal()
{
	qDBusRegisterMetaType<shortcut>();
	qDBusRegisterMetaType<QList<shortcut>>();
	const QString handleToken = getNextToken();
	auto createSession = QDBusMessage::createMethodCall(portalName(), portalPath(), globalShortcutsInterface(), u"CreateSession"_s);
	createSession << QVariantMap{{u"handle_token"_s, handleToken}, {u"session_handle_token"_s, u"obs"_s}};
	new Request(createSession, handleToken, [](uint response, const QVariantMap &results, Request *request){
		delete request;
		if (response != 0) {
			qWarning() << "Creating global shortcut session denied or cancelled";
			return;
		}
		new ShortcutsSession(results.value(u"session_handle"_s).toString(), qApp);
	});

}

#include "platform-wayland.moc"
