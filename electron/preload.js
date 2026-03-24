const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("desktopAPI", {
  getAppVersion: () => ipcRenderer.invoke("app:version"),
  loadSession: () => ipcRenderer.invoke("session:load"),
  saveSession: (payload) => ipcRenderer.invoke("session:save", payload),
  openConfigFile: () => ipcRenderer.invoke("config:open"),
  saveConfigFile: (payload) => ipcRenderer.invoke("config:save", payload)
});
