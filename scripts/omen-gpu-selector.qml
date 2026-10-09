import QtQuick
import QtQuick.Window
import QtQuick.Controls
import QtQuick.Layouts

Window {
    width: 520
    height: 360
    minimumWidth: 420
    minimumHeight: 340
    visible: true
    title: "OPEMOS graphics selector"
    color: "#07111f"
    property var inventory: JSON.parse(__OPEMOS_GPU_INVENTORY__)
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 24
        spacing: 12
        Label { text: "Graphics on this computer"; color: "white"; font.pixelSize: 22 }
        Label {
            Layout.fillWidth: true
            text: inventory.internalGraphicsReason || "Hardware inspection failed."
            color: "#cbd5e1"
            wrapMode: Text.WordWrap
        }
        RadioButton { text: "Internal graphics — unavailable"; enabled: false }
        RadioButton {
            text: inventory.gpuLabel
            checked: inventory.gpuPresent === true
            enabled: false
        }
        Label {
            Layout.fillWidth: true
            text: "VM passthrough is separate from host rendering. Switching may interrupt the desktop and require logout or reboot."
            color: "#cbd5e1"
            wrapMode: Text.WordWrap
        }
        Label { Layout.fillWidth: true; text: inventory.applyReason; color: "#fbbf24"; wrapMode: Text.WordWrap }
        Item { Layout.fillHeight: true }
        RowLayout {
            Button { text: "Apply"; enabled: false }
            Button { text: "Close"; onClicked: Qt.quit() }
        }
    }
}
