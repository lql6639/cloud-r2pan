/**
 * WebDAV 协议实现 —— 挂载点 /webdav/*
 *
 * 支持的方法：
 *   OPTIONS   —— 探测 DAV 能力
 *   PROPFIND  —— 列出目录 / 文件属性（Depth: 0/1/infinity）
 *   GET       —— 下载文件
 *   HEAD      —— 仅返回文件元数据
 *   PUT       —— 上传/覆盖文件
 *   DELETE    —— 删除文件或空目录（非空目录递归删除）
 *   MKCOL     —— 创建目录
 *   MOVE      —— 移动 / 重命名 文件或目录
 *   COPY      —— 复制文件或目录
 *
 * 认证：HTTP Basic Auth，用户名密码在管理后台设置（settings.webdav_username / webdav_password_hash）
 * 存储：复用 StorageProvider（R2 / S3），文件元数据存 D1 files 表，目录存 directories 表
 */

import type { Env } from "./types";
import { getSettings } from "./settings";
import { sha256Hex, safeEqual, hmacB64url, randomHex } from "./crypto";
import { createStorageProvider, type StorageProvider } from "./storage";
import { randomId } from "./db";

/* ═══════════ 懒加载 StorageProvider ═══════════ */
let _storagePromise: Promise<StorageProvider> | null = null;
async function storage(env: Env): Promise<StorageProvider> {
  if (!_storagePromise) {
    _storagePromise = (async () => {
      const s = await getSettings(env);
      return createStorageProvider(env, s);
    })();
  }
  return _storagePromise;
}

/* ═══════════ 工具函数 ═══════════ */

/** 路径标准化：确保以 / 开头、不以 / 结尾（根目录除外），并消解 . / .. 段（防路径穿越） */
function normPath(p: string): string {
  try { p = decodeURIComponent(p); } catch { /* 编码非法时保留原串，交由段过滤兜底 */ }
  p = p.replace(/\\/g, "/").replace(/\/+/g, "/");
  const segs: string[] = [];
  for (const seg of p.split("/")) {
    if (!seg || seg === ".") continue;
    if (seg === "..") { segs.pop(); continue; } // 在根目录再往上时 pop 空数组安全，等效于留在根
    segs.push(seg);
  }
  return "/" + segs.join("/");
}

/** 从 WebDAV URL 提取内部路径（去掉 /webdav 前缀） */
function extractInternalPath(urlPath: string): string {
  // /webdav         → /
  // /webdav/        → /
  // /webdav/foo.txt → /foo.txt
  // /webdav/dir/a.txt → /dir/a.txt
  const stripped = urlPath.replace(/^\/webdav/, "");
  return normPath(stripped || "/");
}

/** 从完整 URL 构建 WebDAV href（用于 PROPFIND 响应） */
function buildHref(baseUrl: string, internalPath: string): string {
  const u = new URL(baseUrl);
  const clean = internalPath === "/" ? "" : internalPath;
  return `${u.origin}/webdav${clean}/`;
}

/** RFC 1123 日期格式 */
function rfc1123(date: Date): string {
  return date.toUTCString().replace(/GMT$/, "GMT");
}

/** 将毫秒时间戳转 RFC 1123 */
function tsToRfc1123(ts: number): string {
  return rfc1123(new Date(ts));
}

/* ═══════════ Basic Auth 认证 ═══════════ */

/** 解析 Basic Auth 头 → {username, password} 或 null */
function parseBasicAuth(authHeader: string | null): { username: string; password: string } | null {
  if (!authHeader || !authHeader.startsWith("Basic ")) return null;
  try {
    const decoded = atob(authHeader.slice(6));
    const i = decoded.indexOf(":");
    if (i < 0) return null;
    return { username: decoded.slice(0, i), password: decoded.slice(i + 1) };
  } catch {
    return null;
  }
}

/** 验证 WebDAV Basic Auth */
async function checkWebDAVAuth(req: Request, env: Env): Promise<boolean> {
  const settings = await getSettings(env);
  if (!settings.webdavEnabled) return false;
  if (!settings.webdavPasswordHash) return false;

  // ① WebDAV 客户端：Authorization: Basic xxx
  const auth = parseBasicAuth(req.headers.get("authorization"));
  if (auth) {
    return verifyWebDAVCreds(settings, auth.username, auth.password);
  }

  // ② 浏览器：网页登录后下发的 Cookie（避免浏览器弹原生认证框）
  return verifyWebDAVCookie(req, env, settings);
}

/** 校验用户名 + 密码（salt:sha256 形式存储在 settings 中） */
async function verifyWebDAVCreds(
  settings: { webdavUsername?: string | null; webdavPasswordHash?: string | null },
  username: string,
  password: string
): Promise<boolean> {
  if (username !== settings.webdavUsername) return false;
  const stored = settings.webdavPasswordHash;
  if (!stored) return false;
  const i = stored.indexOf(":");
  if (i < 0) return false;
  const salt = stored.slice(0, i);
  const want = stored.slice(i + 1);
  const got = await sha256Hex(salt + ":" + password);
  return safeEqual(want, got);
}

/* ═══════════ 数据库辅助查询 ═══════════ */

interface DBFile {
  id: string;
  key: string;
  name: string;
  size: number;
  mime: string;
  path: string;
  uploaded_at: number;
}

/** 查找一个文件（精确 path + name） */
async function findFile(env: Env, dir: string, name: string): Promise<DBFile | null> {
  const path = dir === "/" ? `/${name}` : `${dir}/${name}`;
  return await env.db
    .prepare("SELECT id, key, name, size, mime, path, uploaded_at FROM files WHERE path = ?1 AND name = ?2")
    .bind(path, name)
    .first<DBFile>();
}

/** 查找目录是否存在（directories 表 或 有文件直接在其中） */
async function directoryExists(env: Env, path: string): Promise<boolean> {
  path = path === "/" ? "/" : path.replace(/\/$/, "");
  if (path === "/") return true; // 根目录永远存在
  // directories 表
  const dir: any = await env.db.prepare("SELECT 1 FROM directories WHERE path = ?1").bind(path).first();
  if (dir) return true;
  // 有文件直接在这个目录下（不是子目录）
  const child: any = await env.db
    .prepare("SELECT 1 FROM files WHERE path = ?1 LIMIT 1")
    .bind(path)
    .first();
  if (child) return true;
  // 有文件以这个目录开头（更深层）—— 也算存在
  const deeper: any = await env.db
    .prepare("SELECT 1 FROM files WHERE path LIKE ?1 LIMIT 1")
    .bind(path + "/%")
    .first();
  return !!deeper;
}

/** 列出目录的直接子项（文件 + 子目录） */
async function listDirChildren(env: Env, path: string): Promise<{ files: DBFile[]; dirs: string[] }> {
  path = path === "/" ? "" : path; // 查询时根目录用 "" 前缀
  const nextSlash = path ? path + "/" : "/";

  // 1. 直接子文件：path = 父路径 + "/" + name（精确）
  const { results: files } = await env.db
    .prepare("SELECT id, key, name, size, mime, path, uploaded_at FROM files WHERE path LIKE ?1")
    .bind(path === "" ? "/%" : path + "/%")
    .all<DBFile>();

  // 过滤出直接子文件（不是子目录里的）
  const directFiles: DBFile[] = [];
  const subDirSet = new Set<string>();

  for (const f of files) {
    // f.path 类似 "/foo" 或 "/dir/file.txt"
    const relPath = f.path;
    if (path === "") {
      // 根目录下："/foo" → 直接子项；"/sub/foo" → 子目录项
      const parts = relPath.split("/").filter(Boolean);
      if (parts.length === 1) {
        directFiles.push(f);
      } else if (parts.length >= 2) {
        subDirSet.add("/" + parts[0]);
      }
    } else {
      // 子目录下：path="/dir"，f.path="/dir/sub" 或 "/dir/file.txt"
      const rest = relPath.slice(nextSlash.length - 1); // 去掉 "/dir" 前缀
      if (!rest) continue;
      const slashIdx = rest.indexOf("/");
      if (slashIdx < 0) {
        // 直接子文件
        directFiles.push(f);
      } else {
        // 属于某个子目录
        subDirSet.add(nextSlash + rest.slice(0, slashIdx));
      }
    }
  }

  // 2. directories 表里显式创建的子目录
  const dirPrefix = path === "" ? "/" : nextSlash;
  const { results: explicitDirs } = await env.db
    .prepare("SELECT path FROM directories WHERE path LIKE ?1 AND path != ?2")
    .bind(dirPrefix + "%", path === "" ? "/" : path)
    .all<{ path: string }>();

  for (const d of explicitDirs) {
    if (path === "") {
      // 只取第一段
      const parts = d.path.split("/").filter(Boolean);
      if (parts.length >= 1) subDirSet.add("/" + parts[0]);
    } else {
      const rest = d.path.slice(nextSlash.length - 1);
      if (!rest) continue;
      const slashIdx = rest.indexOf("/");
      if (slashIdx < 0) {
        subDirSet.add(d.path);
      } else {
        subDirSet.add(nextSlash + rest.slice(0, slashIdx));
      }
    }
  }

  return { files: directFiles, dirs: Array.from(subDirSet).sort() };
}

/* ═══════════ PROPFIND XML 生成 ═══════════ */

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** 为单个文件生成 propstat XML */
function filePropstat(file: DBFile, href: string): string {
  const displayName = escapeXml(file.name);
  const mime = escapeXml(file.mime || "application/octet-stream");
  const lastModified = tsToRfc1123(file.uploaded_at);
  const creationDate = new Date(file.uploaded_at).toISOString();
  return `
  <response>
    <href>${escapeXml(href)}</href>
    <propstat>
      <prop>
        <resourcetype><collection/></resourcetype>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
    <propstat>
      <prop>
        <getcontentlength>${file.size}</getcontentlength>
        <getcontenttype>${mime}</getcontenttype>
        <getetag>"${file.id}"</getetag>
        <getlastmodified>${lastModified}</getlastmodified>
        <creationdate>${creationDate}</creationdate>
        <displayname>${displayName}</displayname>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>`;
}

function filePropstatAsFile(file: DBFile, href: string): string {
  const displayName = escapeXml(file.name);
  const mime = escapeXml(file.mime || "application/octet-stream");
  const lastModified = tsToRfc1123(file.uploaded_at);
  const creationDate = new Date(file.uploaded_at).toISOString();
  return `
  <response>
    <href>${escapeXml(href)}</href>
    <propstat>
      <prop>
        <resourcetype/>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
    <propstat>
      <prop>
        <getcontentlength>${file.size}</getcontentlength>
        <getcontenttype>${mime}</getcontenttype>
        <getetag>"${file.id}"</getetag>
        <getlastmodified>${lastModified}</getlastmodified>
        <creationdate>${creationDate}</creationdate>
        <displayname>${displayName}</displayname>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>`;
}

/** 目录自身的 propstat */
function dirPropstat(path: string, baseUrl: string): string {
  const href = buildHref(baseUrl, path);
  const displayName = path === "/" ? "/" : path.split("/").filter(Boolean).pop() || "";
  return `
  <response>
    <href>${escapeXml(href)}</href>
    <propstat>
      <prop>
        <resourcetype><collection/></resourcetype>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
    <propstat>
      <prop>
        <getcontenttype>httpd/unix-directory</getcontenttype>
        <getlastmodified>${tsToRfc1123(Date.now())}</getlastmodified>
        <creationdate>${new Date().toISOString()}</creationdate>
        <displayname>${escapeXml(displayName)}</displayname>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>`;
}

/** 生成 multistatus XML 响应 */
function multistatusXML(responses: string[]): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">${responses.join("")}
</D:multistatus>`;
}

/* ═══════════ WebDAV 主入口 ═══════════ */

export async function handleWebDAV(
  req: Request,
  env: Env,
  _ctx: ExecutionContext
): Promise<Response> {
  const url = new URL(req.url);
  const method = req.method.toUpperCase();
  const internalPath = extractInternalPath(url.pathname);

  // 0. 浏览器网页登录 / 登出（不走 Basic Auth，避免弹出原生认证框）
  if (url.pathname === "/webdav/_login" && method === "POST") {
    return handleWebDavWebLogin(req, env);
  }
  if (url.pathname === "/webdav/_logout" && method === "POST") {
    return new Response(null, {
      status: 302,
      headers: { location: "/webdav/", "set-cookie": clearWebDavCookie(), "cache-control": "no-store" },
    });
  }
  // 浏览器直接访问（Accept 含 text/html）→ 给网页界面；WebDAV 客户端不带该头，继续走协议
  if ((method === "GET" || method === "HEAD") && (req.headers.get("accept") ?? "").includes("text/html")) {
    return handleWebDavBrowser(req, env, internalPath);
  }

  // 1. OPTIONS —— 不强制认证（让客户端先探测能力）
  if (method === "OPTIONS") {
    return new Response("", {
      status: 200,
      headers: {
        "Allow": "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY",
        "DAV": "1, 2, 3",
        "Accept-Ranges": "bytes",
        "Cache-Control": "no-store",
      },
    });
  }

  // 2. 认证
  if (!(await checkWebDAVAuth(req, env))) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "WWW-Authenticate": `Basic realm="cloud-r2pan WebDAV"`,
        "Content-Type": "text/plain",
      },
    });
  }

  // 3. 检查根路径限制（settings.webdav_root_path）
  const settings = await getSettings(env);
  if (settings.webdavRootPath && settings.webdavRootPath !== "/") {
    const root = settings.webdavRootPath.replace(/\/+$/, "") || "/";
    if (!internalPath.startsWith(root)) {
      return new Response("Forbidden", { status: 403 });
    }
  }

  // 4. 分发到各方法处理
  switch (method) {
    case "PROPFIND":
      return handlePropfind(req, env, url, internalPath);
    case "GET":
      return handleWebDavGet(req, env, internalPath, false);
    case "HEAD":
      return handleWebDavGet(req, env, internalPath, true);
    case "PUT":
      return handleWebDavPut(req, env, internalPath);
    case "DELETE":
      return handleWebDavDelete(env, internalPath);
    case "MKCOL":
      return handleWebDavMkcol(env, internalPath);
    case "MOVE":
      return handleWebDavMove(req, env, url, internalPath);
    case "COPY":
      return handleWebDavCopy(req, env, url, internalPath);
    default:
      return new Response("Method Not Allowed", { status: 405 });
  }
}

/* ═══════════ PROPFIND ═══════════ */

async function handlePropfind(
  req: Request,
  env: Env,
  url: URL,
  internalPath: string
): Promise<Response> {
  const depth = req.headers.get("depth") || "1"; // 0 / 1 / infinity
  const baseUrl = url.origin;

  const pathExists = await directoryExists(env, internalPath);
  const file = pathExists && internalPath !== "/"
    ? await env.db
        .prepare("SELECT id, key, name, size, mime, path, uploaded_at FROM files WHERE path = ?1 AND name = ?2")
        .bind(internalPath.slice(0, internalPath.lastIndexOf("/")) || "/",
              internalPath.split("/").filter(Boolean).pop() || "")
        .first<DBFile>()
    : null;

  // 检查这到底是个文件还是目录
  if (file && file.path === internalPath) {
    // 这是个文件
    const href = buildHref(baseUrl, internalPath);
    const body = multistatusXML([filePropstatAsFile(file, href)]);
    return new Response(body, {
      status: 207,
      headers: { "Content-Type": "application/xml; charset=utf-8" },
    });
  }

  // 应该是目录
  if (!pathExists) {
    return new Response("Not Found", { status: 404 });
  }

  // Depth: 0 —— 只返回目录自身
  if (depth === "0") {
    const body = multistatusXML([dirPropstat(internalPath, baseUrl)]);
    return new Response(body, {
      status: 207,
      headers: { "Content-Type": "application/xml; charset=utf-8" },
    });
  }

  // Depth: 1 或 infinity —— 返回目录自身 + 子项
  const responses: string[] = [dirPropstat(internalPath, baseUrl)];

  if (depth === "1") {
    const { files, dirs } = await listDirChildren(env, internalPath);
    for (const d of dirs) {
      responses.push(dirPropstat(d, baseUrl));
    }
    for (const f of files) {
      const href = buildHref(baseUrl, f.path);
      responses.push(filePropstatAsFile(f, href));
    }
  } else {
    // infinity —— 递归列出所有
    await collectAll(env, internalPath, baseUrl, responses);
  }

  const body = multistatusXML(responses);
  return new Response(body, {
    status: 207,
    headers: { "Content-Type": "application/xml; charset=utf-8" },
  });
}

/** 递归收集目录下所有子项（Depth: infinity） */
async function collectAll(
  env: Env,
  path: string,
  baseUrl: string,
  responses: string[]
): Promise<void> {
  const { files, dirs } = await listDirChildren(env, path);
  for (const d of dirs) {
    responses.push(dirPropstat(d, baseUrl));
    await collectAll(env, d, baseUrl, responses);
  }
  for (const f of files) {
    const href = buildHref(baseUrl, f.path);
    responses.push(filePropstatAsFile(f, href));
  }
}

/* ═══════════ GET / HEAD ═══════════ */

async function handleWebDavGet(
  req: Request,
  env: Env,
  internalPath: string,
  headOnly: boolean
): Promise<Response> {
  // 拆分为 dir + name
  const lastSlash = internalPath.lastIndexOf("/");
  const dir = lastSlash <= 0 ? "/" : internalPath.slice(0, lastSlash);
  const name = internalPath.slice(lastSlash + 1);

  if (!name) {
    // 目录 —— 返回目录列表或错误
    return new Response("Not a file", { status: 409 });
  }

  const file = await findFile(env, dir, name);
  if (!file) {
    return new Response("Not Found", { status: 404 });
  }

  const st = await storage(env);
  const obj = await st.head(file.key);
  if (!obj) {
    return new Response("Not Found", { status: 404 });
  }

  const headers = new Headers();
  headers.set("Content-Type", obj.contentType);
  headers.set("Content-Length", String(obj.size));
  headers.set("ETag", `"${file.id}"`);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Last-Modified", tsToRfc1123(file.uploaded_at));
  headers.set("Cache-Control", "no-store");

  if (headOnly) {
    return new Response("", { status: 200, headers });
  }

  // 支持 Range 请求
  const rangeHeader = req.headers.get("range");
  if (rangeHeader) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
    if (m) {
      let offset = m[1] === "" ? null : Number(m[1]);
      let end = m[2] === "" ? null : Number(m[2]);
      if (offset === null && end !== null) {
        // 后缀范围 bytes=-N
        offset = obj.size - end;
        end = obj.size - 1;
      } else if (offset !== null) {
        if (end === null) end = obj.size - 1;
        if (end >= obj.size) end = obj.size - 1;
        if (offset > end) {
          return new Response("Range Not Satisfiable", { status: 416, headers: { "Content-Range": `bytes */${obj.size}` } });
        }
      }
      if (offset !== null && end !== null) {
        const len = end - offset + 1;
        headers.set("Content-Range", `bytes ${offset}-${end}/${obj.size}`);
        headers.set("Content-Length", String(len));
        const ranged = await st.get(file.key, { offset, length: len });
        if (!ranged) return new Response("Not Found", { status: 404 });
        return new Response(ranged.body, { status: 206, headers });
      }
    }
  }

  const fullObj = await st.get(file.key);
  if (!fullObj) return new Response("Not Found", { status: 404 });
  return new Response(fullObj.body, { status: 200, headers });
}

/* ═══════════ PUT ═══════════ */

async function handleWebDavPut(
  req: Request,
  env: Env,
  internalPath: string
): Promise<Response> {
  // 拆分为 dir + name
  const lastSlash = internalPath.lastIndexOf("/");
  const dir = lastSlash <= 0 ? "/" : internalPath.slice(0, lastSlash);
  const name = internalPath.slice(lastSlash + 1);

  if (!name) {
    return new Response("No file name", { status: 400 });
  }

  // 父目录必须存在
  if (!(await directoryExists(env, dir))) {
    return new Response("Conflict: parent directory does not exist", { status: 409 });
  }

  const mime = req.headers.get("content-type") || "application/octet-stream";
  const st = await storage(env);

  // 生成文件记录
  const id = randomId(14);
  const key = `files/${id}`;
  const now = Date.now();

  let size = 0;
  try {
    const res = await st.put(key, req.body as any, {
      contentType: mime,
      contentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(name)}`,
    });
    size = res.size;
  } catch (err: any) {
    return new Response(`Storage error: ${err?.message || err}`, { status: 502 });
  }

  // 检查是否已存在同名文件（覆盖）
  const existing = await findFile(env, dir, name);
  if (existing) {
    // 删除旧文件 + 关联的 shares
    try {
      await env.db.batch([
        env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(existing.id),
        env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(existing.id),
        env.db.prepare("DELETE FROM files WHERE id = ?1").bind(existing.id),
      ]);
      await st.delete(existing.key).catch(() => {});
    } catch { /* 忽略清理失败 */ }
  }

  // 插入新文件记录
  const fullPath = dir === "/" ? `/${name}` : `${dir}/${name}`;
  try {
    await env.db.prepare(
      "INSERT INTO files(id, key, name, size, mime, path, uploaded_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    ).bind(id, key, name, size, mime, fullPath, now).run();
  } catch (err: any) {
    // D1 失败 —— 清理 storage
    await st.delete(key).catch(() => {});
    return new Response(`DB error: ${err?.message || err}`, { status: 502 });
  }

  return new Response("", {
    status: existing ? 204 : 201,
    headers: { "ETag": `"${id}"` },
  });
}

/* ═══════════ DELETE ═══════════ */

async function handleWebDavDelete(env: Env, internalPath: string): Promise<Response> {
  if (internalPath === "/") {
    return new Response("Cannot delete root", { status: 403 });
  }

  const lastSlash = internalPath.lastIndexOf("/");
  const dir = lastSlash <= 0 ? "/" : internalPath.slice(0, lastSlash);
  const name = internalPath.slice(lastSlash + 1);

  // 1. 先看是不是文件
  if (name) {
    const file = await findFile(env, dir, name);
    if (file) {
      const st = await storage(env);
      await env.db.batch([
        env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(file.id),
        env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(file.id),
        env.db.prepare("DELETE FROM files WHERE id = ?1").bind(file.id),
      ]);
      await st.delete(file.key).catch(() => {});
      return new Response("", { status: 204 });
    }
  }

  // 2. 看看是不是目录
  if (await directoryExists(env, internalPath)) {
    // 递归删除目录下所有文件
    const st = await storage(env);
    const likePattern = internalPath + "/%";
    const { results: files } = await env.db
      .prepare("SELECT id, key FROM files WHERE path LIKE ?1")
      .bind(likePattern)
      .all<{ id: string; key: string }>();

    for (const f of files) {
      await env.db.batch([
        env.db.prepare("DELETE FROM shares WHERE file_id = ?1").bind(f.id),
        env.db.prepare("DELETE FROM download_logs WHERE file_id = ?1").bind(f.id),
        env.db.prepare("DELETE FROM files WHERE id = ?1").bind(f.id),
      ]);
      await st.delete(f.key).catch(() => {});
    }

    // 删除目录本身（directories 表）
    await env.db.prepare("DELETE FROM directories WHERE path = ?1").bind(internalPath).run();

    return new Response("", { status: 204 });
  }

  return new Response("Not Found", { status: 404 });
}

/* ═══════════ MKCOL ═══════════ */

async function handleWebDavMkcol(env: Env, internalPath: string): Promise<Response> {
  if (internalPath === "/") {
    return new Response("Root exists", { status: 200 });
  }

  // 父目录必须存在
  const parent = internalPath.slice(0, internalPath.lastIndexOf("/")) || "/";
  if (!(await directoryExists(env, parent))) {
    return new Response("Conflict: parent does not exist", { status: 409 });
  }

  // 目标不能是已存在的文件
  const lastSlash = internalPath.lastIndexOf("/");
  const pdir = lastSlash <= 0 ? "/" : internalPath.slice(0, lastSlash);
  const pname = internalPath.slice(lastSlash + 1);
  if (pname) {
    const existingFile = await findFile(env, pdir, pname);
    if (existingFile) {
      return new Response("Method Not Allowed: file exists here", { status: 405 });
    }
  }

  // 已经存在也返回 201（WebDAV 规范）
  try {
    await env.db.prepare(
      "INSERT INTO directories(path, created_at) VALUES(?1, ?2) ON CONFLICT(path) DO NOTHING"
    ).bind(internalPath, Date.now()).run();
  } catch (err: any) {
    return new Response(`DB error: ${err?.message || err}`, { status: 502 });
  }

  return new Response("", { status: 201 });
}

/* ═══════════ MOVE ═══════════ */

async function handleWebDavMove(
  req: Request,
  env: Env,
  url: URL,
  internalPath: string
): Promise<Response> {
  const destHeader = req.headers.get("destination");
  if (!destHeader) {
    return new Response("Missing Destination header", { status: 400 });
  }

  // 从 Destination URL 提取目标路径
  let destPath: string;
  try {
    const destUrl = new URL(destHeader);
    destPath = extractInternalPath(destUrl.pathname);
  } catch {
    return new Response("Invalid Destination", { status: 400 });
  }

  const overwrite = (req.headers.get("overwrite") || "T").toUpperCase() === "T";

  // 检查源是否存在
  const srcExists = await directoryExists(env, internalPath);
  const srcFile = await pathIsFile(env, internalPath);
  if (!srcExists && !srcFile) {
    return new Response("Not Found", { status: 404 });
  }

  // 目标父目录必须存在
  const destParent = destPath.slice(0, destPath.lastIndexOf("/")) || "/";
  if (!(await directoryExists(env, destParent))) {
    return new Response("Conflict", { status: 409 });
  }

  // 检查目标是否存在
  const destExists = await directoryExists(env, destPath);
  const destFile = await pathIsFile(env, destPath);
  if ((destExists || destFile) && !overwrite) {
    return new Response("Precondition Failed: destination exists", { status: 412 });
  }

  // 如果目标已存在，先删除
  if (destExists || destFile) {
    await handleWebDavDelete(env, destPath);
  }

  if (srcFile) {
    // 移动文件
    await moveFile(env, internalPath, destPath);
  } else {
    // 移动目录（递归更新 path）
    await moveDirectory(env, internalPath, destPath);
  }

  return new Response("", { status: destExists || destFile ? 204 : 201 });
}

/* ═══════════ COPY ═══════════ */

async function handleWebDavCopy(
  req: Request,
  env: Env,
  url: URL,
  internalPath: string
): Promise<Response> {
  const destHeader = req.headers.get("destination");
  if (!destHeader) {
    return new Response("Missing Destination header", { status: 400 });
  }

  let destPath: string;
  try {
    const destUrl = new URL(destHeader);
    destPath = extractInternalPath(destUrl.pathname);
  } catch {
    return new Response("Invalid Destination", { status: 400 });
  }

  const overwrite = (req.headers.get("overwrite") || "T").toUpperCase() === "T";

  const srcFile = await pathIsFile(env, internalPath);
  if (!srcFile) {
    return new Response("Only file copy supported", { status: 501 });
  }

  const destParent = destPath.slice(0, destPath.lastIndexOf("/")) || "/";
  if (!(await directoryExists(env, destParent))) {
    return new Response("Conflict", { status: 409 });
  }

  const destFile = await pathIsFile(env, destPath);
  if (destFile && !overwrite) {
    return new Response("Precondition Failed", { status: 412 });
  }
  if (destFile) {
    await handleWebDavDelete(env, destPath);
  }

  const st = await storage(env);
  const srcObj = await st.get(srcFile.key);
  if (!srcObj) return new Response("Source not found", { status: 404 });

  const newId = randomId(14);
  const newKey = `files/${newId}`;
  const newName = destPath.split("/").filter(Boolean).pop() || srcFile.name;

  await st.put(newKey, srcObj.body, { contentType: srcFile.mime });

  await env.db.prepare(
    "INSERT INTO files(id, key, name, size, mime, path, uploaded_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)"
  ).bind(newId, newKey, newName, srcFile.size, srcFile.mime, destPath, Date.now()).run();

  return new Response("", { status: 201 });
}

/* ═══════════ 辅助：判断路径是否是文件 ═══════════ */

async function pathIsFile(env: Env, p: string): Promise<DBFile | null> {
  const lastSlash = p.lastIndexOf("/");
  const dir = lastSlash <= 0 ? "/" : p.slice(0, lastSlash);
  const name = p.slice(lastSlash + 1);
  if (!name) return null;
  return await findFile(env, dir, name);
}

/* ═══════════ 辅助：移动文件 ═══════════ */

async function moveFile(env: Env, srcPath: string, destPath: string): Promise<void> {
  const srcLast = srcPath.lastIndexOf("/");
  const srcDir = srcLast <= 0 ? "/" : srcPath.slice(0, srcLast);
  const srcName = srcPath.slice(srcLast + 1);

  const file = await findFile(env, srcDir, srcName);
  if (!file) return;

  const destLast = destPath.lastIndexOf("/");
  const destDir = destLast <= 0 ? "/" : destPath.slice(0, destLast);
  const destName = destPath.slice(destLast + 1);
  const fullDestPath = destDir === "/" ? `/${destName}` : `${destDir}/${destName}`;

  await env.db.prepare(
    "UPDATE files SET path = ?1, name = ?2 WHERE id = ?3"
  ).bind(fullDestPath, destName, file.id).run();
}

/* ═══════════ 辅助：移动目录（递归更新 path 前缀） ═══════════ */

async function moveDirectory(env: Env, srcDir: string, destDir: string): Promise<void> {
  const likePattern = srcDir === "/" ? "/%" : srcDir + "/%";
  const { results: files } = await env.db
    .prepare("SELECT id, path FROM files WHERE path LIKE ?1")
    .bind(likePattern)
    .all<{ id: string; path: string }>();

  for (const f of files) {
    let newPath: string;
    if (srcDir === "/") {
      newPath = destDir + f.path;
      if (!newPath.startsWith("/")) newPath = "/" + newPath;
    } else {
      newPath = destDir + f.path.slice(srcDir.length);
    }
    await env.db.prepare("UPDATE files SET path = ?1 WHERE id = ?2").bind(newPath, f.id).run();
  }

  // 也更新 directories 表中的子目录记录
  const { results: dirs } = await env.db
    .prepare("SELECT path FROM directories WHERE path LIKE ?1")
    .bind(likePattern)
    .all<{ path: string }>();

  for (const d of dirs) {
    let newPath: string;
    if (srcDir === "/") {
      newPath = destDir + d.path;
    } else {
      newPath = destDir + d.path.slice(srcDir.length);
    }
    await env.db.prepare("DELETE FROM directories WHERE path = ?1").bind(d.path).run();
    await env.db.prepare("INSERT INTO directories(path, created_at) VALUES(?1, ?2) ON CONFLICT(path) DO NOTHING")
      .bind(newPath, Date.now()).run();
  }

  // 更新目录本身
  await env.db.prepare("DELETE FROM directories WHERE path = ?1").bind(srcDir).run();
  await env.db.prepare("INSERT INTO directories(path, created_at) VALUES(?1, ?2) ON CONFLICT(path) DO NOTHING")
    .bind(destDir, Date.now()).run();
}

/* ═══════════════════════════════════════════════════════════
 * 浏览器网页界面 —— 登录页 + 目录浏览
 * 只拦截 Accept: text/html 的 GET；WebDAV 客户端不带 text/html，仍走 Basic Auth。
 * 网页登录成功下发 HMAC 签名 Cookie，避免浏览器弹原生认证框。
 * ═══════════════════════════════════════════════════════════ */

const WD_COOKIE = "wd_auth";
const WD_TTL_MS = 7 * 24 * 3600 * 1000;

function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

async function wdCookieSig(env: Env, settings: any, exp: number): Promise<string> {
  const fp = (settings.webdavPasswordHash ?? "").slice(0, 12);
  return hmacB64url(env.admin, `wd:${settings.webdavUsername ?? ""}:${fp}:${exp}`);
}

async function buildWebDavCookie(req: Request, env: Env, settings: any): Promise<string> {
  const exp = Date.now() + WD_TTL_MS;
  const sig = await wdCookieSig(env, settings, exp);
  const secure = new URL(req.url).protocol === "https:" ? "; Secure" : "";
  return `${WD_COOKIE}=${exp}.${sig}; Path=/webdav; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(WD_TTL_MS / 1000)}${secure}`;
}

function clearWebDavCookie(): string {
  return `${WD_COOKIE}=; Path=/webdav; HttpOnly; SameSite=Lax; Max-Age=0`;
}

/** Cookie 会话校验：签名 + 过期；密码变更后指纹变化，旧 Cookie 自动失效 */
async function verifyWebDAVCookie(req: Request, env: Env, settings: any): Promise<boolean> {
  const raw = parseCookies(req.headers.get("cookie"))[WD_COOKIE];
  if (!raw) return false;
  const i = raw.indexOf(".");
  if (i < 0) return false;
  const exp = Number(raw.slice(0, i));
  const sig = raw.slice(i + 1);
  if (!Number.isFinite(exp) || exp < Date.now()) return false;
  return safeEqual(sig, await wdCookieSig(env, settings, exp));
}

function escHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!)
  );
}

function fmtSize(n: number): string {
  if (!n) return "-";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

const WD_CSS = `
*{margin:0;padding:0;box-sizing:border-box}
html{background:#080b18}
body{min-height:100vh;padding:32px 20px;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Microsoft YaHei",sans-serif;
  color:#e9eef8;background:radial-gradient(120% 90% at 50% 0%,#141a33 0%,#0a0e1e 55%,#070a14 100%)}
.wrap{max-width:400px;margin:0 auto}
.wrap.center{min-height:calc(100vh - 64px);display:flex;align-items:center}
.wrap.center .card{width:100%;margin:0 auto}
.card{background:rgba(255,255,255,.055);border:1px solid rgba(255,255,255,.12);border-radius:22px;padding:28px;
  box-shadow:0 18px 50px rgba(0,0,0,.42);backdrop-filter:blur(20px)}
.brand{display:flex;align-items:center;gap:14px;margin-bottom:22px}
.logo{width:46px;height:46px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:22px;
  background:linear-gradient(145deg,rgba(255,255,255,.2),rgba(255,255,255,.05));border:1px solid rgba(255,255,255,.22)}
h1{font-size:21px;font-weight:700;letter-spacing:-.01em}
.brand p{font-size:12.5px;color:#8b95ad;margin-top:3px}
label{display:block;font-size:12.5px;color:#9aa4bb;margin:14px 0 6px}
input{width:100%;padding:13px 15px;border-radius:14px;font-size:15px;font-family:inherit;color:#e9eef8;
  background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);outline:none}
input:focus{border-color:rgba(70,150,255,.75);background:rgba(255,255,255,.1)}
button{margin-top:20px;width:100%;padding:13px;border-radius:14px;border:none;cursor:pointer;font-size:15px;font-weight:600;
  color:#fff;background:linear-gradient(180deg,#3d9bff,#0a7cff);box-shadow:0 8px 22px rgba(10,124,255,.35)}
button:hover{filter:brightness(1.06)}
.err{margin-top:12px;font-size:13px;color:#ff9688}
.hint{margin-top:18px;font-size:12px;line-height:1.75;color:#7b859d}
code{padding:1px 6px;border-radius:6px;background:rgba(255,255,255,.09);font-family:ui-monospace,Menlo,monospace;font-size:11.5px}
.crumb{display:flex;flex-wrap:wrap;align-items:center;gap:6px;font-size:13px;color:#9aa4bb;margin-bottom:16px}
.crumb a{color:#6fb2ff;text-decoration:none}
.crumb a:hover{text-decoration:underline}
.list{margin-top:6px;border-radius:16px;overflow:hidden;border:1px solid rgba(255,255,255,.1)}
.row{display:flex;align-items:center;gap:12px;padding:12px 15px;font-size:14px;border-bottom:1px solid rgba(255,255,255,.07)}
.row:last-child{border-bottom:none}
.row:hover{background:rgba(255,255,255,.05)}
.row a{flex:1;color:#e9eef8;text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row a:hover{color:#6fb2ff}
.ico{width:22px;text-align:center;flex:none;font-size:16px}
.meta{flex:none;color:#7b859d;font-size:12px}
.empty{padding:28px;text-align:center;color:#7b859d;font-size:13px}
.bar{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.bar form{margin:0}
.bar button{margin:0;width:auto;padding:8px 14px;font-size:12.5px;border-radius:11px;background:rgba(255,255,255,.1);
  color:#c7d0e3;box-shadow:none;font-weight:500}
.bar button:hover{background:rgba(255,255,255,.16)}
`;

function wdPage(title: string, body: string, status = 200, centered = false): Response {
  const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>${escHtml(title)}</title><link rel="icon" href="/favicon.ico" type="image/x-icon">
<style>${WD_CSS}</style></head><body><div class="wrap${centered ? " center" : ""}">${body}</div></body></html>`;
  return new Response(html, {
    status,
    headers: {
      "content-type": "text/html;charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
    },
  });
}

function wdLoginPage(site: string, error?: string, status = 200): Response {
  return wdPage(
    `${site} · WebDAV 登录`,
    `<div class="card">
      <div class="brand"><div class="logo">🗂️</div><div><h1>${escHtml(site)}</h1><p>WebDAV 文件访问</p></div></div>
      <form method="POST" action="/webdav/_login">
        <label>用户名</label><input name="username" autocomplete="username" autofocus>
        <label>密码</label><input name="password" type="password" autocomplete="current-password">
        ${error ? `<div class="err">${escHtml(error)}</div>` : ""}
        <button type="submit">登录</button>
      </form>
    </div>`,
    status,
    true
  );
}

/** POST /webdav/_login —— 网页表单登录 */
async function handleWebDavWebLogin(req: Request, env: Env): Promise<Response> {
  const s = await getSettings(env);
  const site = s.siteTitle || "cloud-r2pan";
  if (!s.webdavEnabled || !s.webdavPasswordHash) {
    return wdPage(`${site} · WebDAV`, `<div class="card"><h1>WebDAV 未启用</h1>
      <p class="hint">请在后台「系统设置 → WebDAV」中开启服务并设置密码。</p></div>`, 403);
  }
  let form: FormData | null = null;
  try {
    form = await req.formData();
  } catch {
    return wdLoginPage(site, "请求格式错误，请重新登录", 400);
  }
  const username = String(form.get("username") ?? "").trim();
  const password = String(form.get("password") ?? "");
  if (!(await verifyWebDAVCreds(s, username, password))) {
    return wdLoginPage(site, "用户名或密码错误", 401);
  }
  return new Response(null, {
    status: 302,
    headers: {
      location: "/webdav/",
      "set-cookie": await buildWebDavCookie(req, env, s),
      "cache-control": "no-store",
    },
  });
}

/** GET（Accept: text/html）—— 未登录给登录页，已登录给目录列表 */
async function handleWebDavBrowser(
  req: Request,
  env: Env,
  internalPath: string
): Promise<Response> {
  const s = await getSettings(env);
  const site = s.siteTitle || "cloud-r2pan";
  if (!s.webdavEnabled || !s.webdavPasswordHash) {
    return wdPage(
      `${site} · WebDAV`,
      `<div class="card"><h1>WebDAV 未启用</h1><p class="hint">请在后台「系统设置 → WebDAV」中开启服务并设置密码。</p></div>`,
      403
    );
  }
  if (!(await verifyWebDAVCookie(req, env, s))) return wdLoginPage(site);

  // 目录浏览
  const clean = internalPath === "/" ? "/" : internalPath.replace(/\/+$/, "") + "/";
  const prefix = clean === "/" ? "" : clean.replace(/^\//, "");
  let entries: any[] = [];
  let truncated = false;
  try {
    const st = await storage(env);
    const r = await st.list({ prefix, limit: 500 });
    entries = r.entries ?? [];
    truncated = r.truncated;
  } catch (err: any) {
    return wdPage(
      `${site} · WebDAV`,
      `<div class="card"><h1>读取目录失败</h1><p class="hint">${escHtml(String(err?.message ?? err))}</p></div>`,
      500
    );
  }

  entries.sort((a, b) => (a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1));

  // 面包屑
  const parts = clean.split("/").filter(Boolean);
  let acc = "/";
  const crumbs = [`<a href="/webdav/">根目录</a>`];
  for (const p of parts) {
    acc += p + "/";
    crumbs.push(`<span>/</span><a href="/webdav/${escHtml(encodeURI(acc))}">${escHtml(p)}</a>`);
  }

  const rows = entries
    .map((e) => {
      const href = `/webdav/${escHtml(encodeURI(clean + e.name))}`;
      return `<div class="row"><span class="ico">${e.isDir ? "📁" : "📄"}</span>
        <a href="${href}">${escHtml(e.name)}</a>
        <span class="meta">${e.isDir ? "文件夹" : fmtSize(e.size)}</span></div>`;
    })
    .join("");

  const body = `<div class="bar">
      <div class="brand" style="margin:0"><div class="logo">🗂️</div>
        <div><h1>${escHtml(site)}</h1><p>WebDAV · ${escHtml(s.webdavUsername || "share")}</p></div></div>
      <form method="POST" action="/webdav/_logout"><button type="submit">退出</button></form>
    </div>
    <div class="crumb">${crumbs.join("")}</div>
    <div class="list">${rows || `<div class="empty">这个目录是空的</div>`}</div>
    ${truncated ? `<p class="hint">条目过多，仅显示前 500 项。</p>` : ""}`;

  return wdPage(`${site} · ${clean}`, body);
}
