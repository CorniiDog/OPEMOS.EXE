import QtQuick
import QtQuick.Window
import QtWebEngine

Window {
    id: installerWindow
    visible: true
    visibility: Window.FullScreen
    color: "#07111f"
    title: "Install SteamOS with NVIDIA drivers"

    WebEngineProfile {
        id: privateProfile
        offTheRecord: true
        persistentCookiesPolicy: WebEngineProfile.NoPersistentCookies
        httpCacheType: WebEngineProfile.MemoryHttpCache
    }

    WebEngineView {
        anchors.fill: parent
        profile: privateProfile
        url: "__OPEMOS_INSTALLER_URL__"
    }
}
