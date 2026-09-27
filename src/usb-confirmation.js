export const USB_CONFIRMATION_PHRASE = "ERASE";

export function usbConfirmationMatches(value) {
  return value === USB_CONFIRMATION_PHRASE;
}

export function usbConfirmationForBackend(deviceIdentifier, value) {
  if (typeof deviceIdentifier !== "string" || !deviceIdentifier) {
    throw new TypeError("A selected USB device identifier is required");
  }
  if (!usbConfirmationMatches(value)) {
    throw new Error(`Type ${USB_CONFIRMATION_PHRASE} exactly to continue.`);
  }
  return `${USB_CONFIRMATION_PHRASE} ${deviceIdentifier}`;
}
