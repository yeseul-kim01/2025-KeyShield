import { LOG_PREFIX } from "./constants.js";

export function log(message, payload) {
  if (payload) console.log(LOG_PREFIX, message, payload);
  else console.log(LOG_PREFIX, message);
}

export function warn(message, payload) {
  if (payload) console.warn(LOG_PREFIX, message, payload);
  else console.warn(LOG_PREFIX, message);
}
