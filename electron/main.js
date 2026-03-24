const { app, BrowserWindow, dialog, ipcMain } = require("electron");
const fs = require("fs");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");

const SESSION_KEY = "workspace-session";
let db;

function getDb() {
  if (db) return db;
  const dbPath = path.join(app.getPath("userData"), "proxy-asset-composer.db");
  db = new DatabaseSync(dbPath);
  db.exec(`
    CREATE TABLE IF NOT EXISTS app_state (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  return db;
}

function saveSession(session) {
  const database = getDb();
  const stmt = database.prepare(`
    INSERT INTO app_state (key, value, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET
      value = excluded.value,
      updated_at = excluded.updated_at
  `);
  stmt.run(SESSION_KEY, JSON.stringify(session));
  return { ok: true };
}

function loadSession() {
  const database = getDb();
  const stmt = database.prepare("SELECT value FROM app_state WHERE key = ?");
  const row = stmt.get(SESSION_KEY);
  if (!row) return null;
  try {
    return JSON.parse(row.value);
  } catch {
    return null;
  }
}

async function openConfigFile() {
  const { canceled, filePaths } = await dialog.showOpenDialog({
    title: "选择 Clash 配置文件",
    properties: ["openFile"],
    filters: [{ name: "Config", extensions: ["yaml", "yml", "txt"] }]
  });
  if (canceled || !filePaths.length) return null;

  const filePath = filePaths[0];
  return {
    filePath,
    text: fs.readFileSync(filePath, "utf8")
  };
}

async function saveConfigFile(payload) {
  const { defaultPath, content } = payload;
  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "导出 Clash 配置",
    defaultPath,
    filters: [{ name: "Config", extensions: ["yaml", "yml", "txt"] }]
  });
  if (canceled || !filePath) return null;
  fs.writeFileSync(filePath, content, "utf8");
  return { filePath };
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1480,
    height: 980,
    minWidth: 1180,
    minHeight: 760,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  win.loadFile(path.join(__dirname, "..", "app", "index.html"));
}

app.whenReady().then(() => {
  ipcMain.handle("app:version", () => app.getVersion());
  ipcMain.handle("session:load", () => loadSession());
  ipcMain.handle("session:save", (_event, payload) => saveSession(payload));
  ipcMain.handle("config:open", () => openConfigFile());
  ipcMain.handle("config:save", (_event, payload) => saveConfigFile(payload));

  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
