import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import net from 'node:net';

let root, child, url, port, peerPort;
const binary = path.resolve('target/debug/rustorrent');
function encode(value) {
  if (Buffer.isBuffer(value)) return Buffer.concat([Buffer.from(value.length + ':'), value]);
  if (typeof value === 'string') return encode(Buffer.from(value));
  if (typeof value === 'number') return Buffer.from('i' + value + 'e');
  if (Array.isArray(value)) return Buffer.concat([Buffer.from('l'), ...value.map(encode), Buffer.from('e')]);
  return Buffer.concat([Buffer.from('d'), ...Object.keys(value).sort().flatMap(key => [encode(key), encode(value[key])]), Buffer.from('e')]);
}
const payload = Buffer.from('independent browser fixture\n');
function torrent(name, data = payload) {
  return encode({info: {name, length: data.length, 'piece length': 16384, pieces: createHash('sha1').update(data).digest(), private: 1}});
}
function multiTorrent(name) {
  const files = [['one.txt', 'first file\n'], ['two.txt', 'second file\n']].map(([file, text]) => ({path: [file], length: text.length, text}));
  const joined = Buffer.from(files.map(file => file.text).join(''));
  return encode({info: {name, files: files.map(({path, length}) => ({path, length})), 'piece length': 16384, pieces: createHash('sha1').update(joined).digest(), private: 1}});
}
async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const result = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return result;
}
async function start() {
  child = spawn(binary, ['--ui', '--ui-addr', `127.0.0.1:${port}`, '--port', String(peerPort), '--download-dir', root, '--proxy', 'socks5://127.0.0.1:9'], {stdio: 'ignore'});
  await expect.poll(async () => { try { return (await fetch(url + '/status')).status; } catch { return 0; } }).toBe(200);
}
async function stop() {
  if (!child || child.exitCode !== null) return;
  const exited = new Promise(resolve => child.once('exit', resolve));
  child.kill('SIGTERM');
  await exited;
}
async function post(endpoint, body = undefined, type = 'application/x-www-form-urlencoded') {
  const {token} = await (await fetch(url + '/api-token')).json();
  const response = await fetch(url + endpoint, {method: 'POST', headers: {Origin: url, 'X-Rustorrent-Token': token, 'Content-Type': type}, body});
  const result = await response.json();
  expect(response.ok, JSON.stringify(result)).toBeTruthy();
  return result;
}
async function state() { return (await fetch(url + '/status')).json(); }
const find = async name => (await state()).torrents.find(t => t.name === name);
async function add(name, paused = false, seed = true) {
  if (seed) await writeFile(path.join(root, name), payload);
  await post('/add-torrent?paused=' + (paused ? '1' : '0'), torrent(name), 'application/x-bittorrent');
  await expect.poll(async () => (await find(name))?.files.length || 0).toBe(1);
  return (await find(name)).id;
}
const row = (page, name) => page.locator('.row').filter({hasText: name});
// Collects page errors and Content-Security-Policy violations.
function watchErrors(page) {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (/Content Security Policy/i.test(message.text())) errors.push(message.text()); });
  return errors;
}
async function axe(page) {
  // Scan the settled page: mid-fade text would be measured as low contrast.
  await page.waitForFunction(() => document.getAnimations().every(a => a.playState !== 'running'));
  const scan = await new AxeBuilder({page}).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  return scan.violations.map(v => ({id: v.id, nodes: v.nodes.map(n => n.target)}));
}

test.beforeAll(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'rustorrent-browser-'));
  port = await freePort(); peerPort = await freePort(); url = `http://127.0.0.1:${port}`;
  await start();
});
test.afterAll(async () => { await stop(); if (root) await rm(root, {recursive: true, force: true}); });
test.beforeEach(async () => {
  for (const item of (await state()).torrents) await post(`/torrent/delete?id=${item.id}&data=0`);
  await expect.poll(async () => (await state()).torrents.length).toBe(0);
});

test('shell loads cached assets and the stream sends JSON deltas', async () => {
  const html = await (await fetch(url + '/')).text();
  expect(html.length).toBeLessThan(2048);
  expect(html).toContain('<script src="/app.js" defer></script>');
  for (const asset of ['/app.css', '/app.js']) {
    const first = await fetch(url + asset);
    expect(first.status).toBe(200);
    expect(first.headers.get('cache-control')).toBe('no-cache');
    const etag = first.headers.get('etag');
    expect(etag).toMatch(/^"[0-9a-f]{8}"$/);
    expect((await fetch(url + asset, {headers: {'If-None-Match': etag}})).status).toBe(304);
  }
  await add('Stream check.txt');
  const controller = new AbortController();
  const response = await fetch(url + '/events', {signal: controller.signal});
  const reader = response.body.getReader();
  let text = '';
  while (!text.includes('\n\nevent: status') || !text.endsWith('\n\n')) text += new TextDecoder().decode((await reader.read()).value);
  controller.abort();
  const event = JSON.parse(text.split('\n').find(line => line.startsWith('data: ')).slice(6));
  expect(event.g.version).toBeTruthy();
  expect(event.ids.length).toBe(1);
  expect(event.t[0]).toMatchObject({name: 'Stream check.txt', file_count: 1});
  expect(event.t[0].files).toBeUndefined();
  const files = await (await fetch(`${url}/torrent/files?id=${event.t[0].id}`)).json();
  expect(files.files[0]).toMatchObject({path: 'Stream check.txt', priority: 2});
});

test('empty library, keyboard dialog, inline validation, focus restoration', async ({page}) => {
  const errors = watchErrors(page);
  await page.goto(url);
  await expect(page.getByRole('heading', {name: 'All transfers', exact: true})).toBeVisible();
  await expect(page.getByRole('heading', {name: 'No transfers yet'})).toBeVisible();
  await page.getByRole('button', {name: 'Add your first torrent'}).click();
  const dialog = page.getByRole('dialog', {name: 'Add torrent'});
  const addButton = dialog.getByRole('button', {name: 'Add', exact: true});
  await expect(dialog.getByLabel('Magnet link')).toBeFocused();
  await expect(addButton).toBeDisabled();
  await dialog.getByLabel('Magnet link').fill('not-a-magnet');
  await expect(dialog.locator('#addSummary')).toContainText('Enter a valid magnet');
  await expect(addButton).toBeDisabled();
  await dialog.getByLabel('Magnet link').fill('magnet:?xt=urn:btih:' + 'a'.repeat(40) + '&xt=urn:btih:' + 'b'.repeat(40));
  await addButton.click();
  await expect(dialog.getByRole('alert')).toContainText('Could not add torrent');
  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();
  await expect(page.getByRole('button', {name: 'Add your first torrent'})).toBeFocused();
  expect(errors).toEqual([]);
});

test('browser upload starts paused and survives restart', async ({page}) => {
  await page.goto(url); await page.getByRole('button', {name: 'Add', exact: true}).click();
  const dialog = page.getByRole('dialog', {name: 'Add torrent'});
  await dialog.getByLabel('Torrent file', {exact: true}).setInputFiles({name: 'readme.torrent', mimeType: 'application/x-bittorrent', buffer: torrent('Read me.txt')});
  await expect(dialog.locator('#addSummary')).toContainText('1 file');
  await dialog.getByLabel('Start immediately').uncheck();
  await dialog.getByRole('button', {name: 'Add', exact: true}).click();
  await expect(page.locator('.toast')).toContainText('Torrent added paused');
  const item = row(page, 'Read me.txt');
  await expect(item.getByRole('button', {name: 'Resume', exact: true})).toBeEnabled();
  await expect(item.locator('.pill')).toHaveText('Paused');
  expect((await state()).torrents[0].paused).toBe(true);
  await stop(); await start();
  await expect.poll(async () => (await state()).torrents[0]?.paused).toBe(true);
  // Ids are reassigned on restart; wait until the live stream has reconnected.
  const restartedId = (await state()).torrents[0].id;
  await expect(page.locator(`.row[data-id="${restartedId}"]`)).toBeVisible({timeout: 10000});
  await expect(page.locator('#conn')).toBeHidden();
  await item.getByRole('button', {name: 'Resume', exact: true}).click();
  await expect(item.getByRole('button', {name: 'Pause', exact: true})).toBeEnabled();
});

test('multi-file preview skips deselected files, drag and drop, magnet paste', async ({page}) => {
  await page.goto(url);
  const dialog = page.getByRole('dialog', {name: 'Add torrent'});
  const bytes = [...multiTorrent('Two files')];
  const dataTransfer = await page.evaluateHandle(data => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([new Uint8Array(data)], 'two.torrent', {type: 'application/x-bittorrent'}));
    return transfer;
  }, bytes);
  await page.dispatchEvent('main', 'drop', {dataTransfer});
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('#addSummary')).toHaveText('2 files · 23 B');
  await dialog.getByRole('checkbox', {name: /^two\.txt/}).uncheck();
  await expect(dialog.locator('#addSummary')).toContainText('1 selected');
  await dialog.getByLabel('Select all files').check();
  await expect(dialog.locator('#addSummary')).toHaveText('2 files · 23 B');
  await dialog.getByLabel('Select all files').uncheck();
  await expect(dialog.getByRole('button', {name: 'Add', exact: true})).toBeDisabled();
  await dialog.getByRole('checkbox', {name: /^one\.txt/}).check();
  await dialog.getByRole('button', {name: 'Add', exact: true}).click();
  await expect.poll(async () => (await find('Two files'))?.files.map(f => f.priority).join()).toBe('2,0');
  await page.evaluate(() => {
    const data = new DataTransfer();
    data.setData('text/plain', 'magnet:?xt=urn:btih:' + 'c'.repeat(40));
    document.body.dispatchEvent(new ClipboardEvent('paste', {clipboardData: data, bubbles: true}));
  });
  await expect(dialog.getByLabel('Magnet link')).toHaveValue('magnet:?xt=urn:btih:' + 'c'.repeat(40));
  await expect(dialog.locator('#addSummary')).toHaveText('Magnet link ready to add.');
});

test('sidebar filters, search field and expanded inputs survive live updates', async ({page}) => {
  const errors = watchErrors(page);
  await add('Field recordings.txt'); const paused = await add('Release notes.txt', true);
  await page.goto(url);
  await expect(page.locator('.row')).toHaveCount(2);
  const nav = page.getByRole('navigation', {name: 'Sections'});
  await nav.getByRole('button', {name: /^Paused/}).click();
  await expect(page.getByRole('heading', {name: 'Paused'})).toBeVisible();
  await expect(page.locator('.row:visible')).toHaveCount(1);
  await expect(row(page, 'Release notes.txt')).toBeVisible();
  await nav.getByRole('button', {name: /^All/}).click();
  await page.getByLabel('Filter transfers').fill('no matching name');
  await expect(page.locator('#nomatch')).toBeVisible();
  await page.getByRole('button', {name: 'Show all transfers'}).click();
  await expect(page.locator('.row:visible')).toHaveCount(2);

  const item = row(page, 'Field recordings.txt');
  await item.locator('.rn').click();
  await expect(item.locator('.rn')).toHaveAttribute('aria-expanded', 'true');
  await item.getByRole('tab', {name: 'Info'}).click();
  const input = item.getByLabel('Transfer label'); await input.fill('Work in progress');
  await post(`/torrent/pause?id=${paused}`);
  await post(`/torrent/resume?id=${paused}`);
  await page.waitForTimeout(1100);
  await expect(input).toHaveValue('Work in progress'); await expect(input).toBeFocused();
  await input.press('Enter');
  await expect(nav.getByRole('button', {name: /^Work in progress/})).toBeVisible();
  await expect.poll(async () => (await find('Field recordings.txt')).label).toBe('Work in progress');
  await page.reload();
  await expect(row(page, 'Field recordings.txt').getByRole('tab', {name: 'Info'})).toHaveAttribute('aria-selected', 'true');
  expect(errors).toEqual([]);
});

test('keyboard shortcuts select, pause and remove transfers', async ({page}) => {
  await add('Keyboard one.txt'); await add('Keyboard two.txt');
  await page.goto(url);
  await expect(page.locator('.row')).toHaveCount(2);
  await page.keyboard.press('/');
  await expect(page.getByLabel('Filter transfers')).toBeFocused();
  await page.keyboard.press('Escape');
  await page.locator('body').click({position: {x: 5, y: 700}});
  await page.keyboard.press('ArrowDown');
  await expect(row(page, 'Keyboard one.txt')).toHaveClass(/sel/);
  await page.keyboard.press('ArrowDown');
  await expect(row(page, 'Keyboard two.txt').locator('.rn')).toBeFocused();
  await page.keyboard.press(' ');
  await expect.poll(async () => (await find('Keyboard two.txt')).paused).toBe(true);
  await expect(row(page, 'Keyboard two.txt').locator('.rn')).toHaveAttribute('aria-expanded', 'false');
  await page.keyboard.press('Enter');
  await expect(row(page, 'Keyboard two.txt').locator('.rn')).toHaveAttribute('aria-expanded', 'true');
  await page.keyboard.press('Delete');
  const dialog = page.getByRole('dialog', {name: 'Remove transfer?'});
  await expect(dialog).toContainText('Keyboard two.txt');
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await page.keyboard.press('a');
  await expect(page.getByRole('dialog', {name: 'Add torrent'})).toBeVisible();
});

test('files, trackers and settings controls reach the engine', async ({page}) => {
  await writeFile(path.join(root, 'Prioritized.txt'), payload);
  await post('/add-torrent', torrent('Prioritized.txt'), 'application/x-bittorrent');
  await expect.poll(async () => (await find('Prioritized.txt'))?.files.length || 0).toBe(1);
  await page.goto(url);
  const item = row(page, 'Prioritized.txt');
  await item.locator('.rn').click();
  await item.getByRole('tab', {name: 'Files'}).click();
  await item.getByLabel('File priority').selectOption('3');
  await expect.poll(async () => (await find('Prioritized.txt')).files[0].priority).toBe(3);
  await item.getByRole('tab', {name: 'Files'}).press('ArrowRight');
  await expect(item.getByRole('tab', {name: 'Trackers'})).toBeFocused();
  await item.getByLabel('Tracker URL').fill('udp://tracker.example.org:1337/announce');
  await item.getByRole('button', {name: 'Add tracker'}).click();
  await expect(item.locator('.tp:visible')).toContainText('udp://tracker.example.org:1337/announce');
  await item.getByRole('button', {name: 'Remove tracker udp://tracker.example.org:1337/announce'}).click();
  await expect.poll(async () => (await find('Prioritized.txt')).trackers.length).toBe(0);

  await page.getByRole('button', {name: /^Settings/}).click();
  await page.getByLabel('Download limit').fill('512');
  await page.getByLabel('Download limit').press('Tab');
  await expect.poll(async () => (await state()).global_download_limit_bps).toBe(512 * 1024);
  await expect(page.getByLabel('Connections per transfer')).toHaveValue('100');
  await page.getByLabel('Connections per transfer').fill('150');
  await page.getByLabel('Connections per transfer').press('Tab');
  await expect.poll(async () => (await state()).peer_profile_torrent_limit).toBe(150);
  await page.getByLabel('Peer profile').selectOption('conservative');
  await expect.poll(async () => (await state()).peer_profile).toBe('conservative');
  // Choosing a profile replaces a hand-set limit with the profile's own.
  await expect.poll(async () => (await state()).peer_profile_torrent_limit).toBe(30);
  await page.getByLabel('Theme', {exact: true}).selectOption('dark');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.getByLabel('Download limit').fill('0'); await page.getByLabel('Download limit').press('Tab');
  await page.getByLabel('Peer profile').selectOption('balanced');
  await expect.poll(async () => (await state()).global_download_limit_bps).toBe(0);
});

test('remove dialog keeps files by default and deletes only when selected', async ({page}) => {
  await add('Keep this.txt'); await page.goto(url);
  await row(page, 'Keep this.txt').getByRole('button', {name: 'Remove', exact: true}).click();
  const dialog = page.getByRole('dialog', {name: 'Remove transfer?'});
  await expect(dialog.getByLabel('Also delete downloaded files')).not.toBeChecked();
  await dialog.getByRole('button', {name: 'Remove transfer', exact: true}).click();
  await expect(page.locator('.row')).toHaveCount(0);
  expect(await readFile(path.join(root, 'Keep this.txt'), 'utf8')).toBe('independent browser fixture\n');
  await add('Delete this.txt');
  await expect(page.locator('.row')).toHaveCount(1);
  await row(page, 'Delete this.txt').getByRole('button', {name: 'Remove', exact: true}).click();
  await dialog.getByLabel('Also delete downloaded files').check();
  await dialog.getByRole('button', {name: 'Remove transfer', exact: true}).click();
  await expect(page.locator('.row')).toHaveCount(0);
  await expect(access(path.join(root, 'Delete this.txt'))).rejects.toThrow();
});

test('desktop, dark, narrow layout, and accessibility', async ({page}) => {
  const errors = watchErrors(page);
  await add('Ubuntu installation notes.txt'); await add('Archive of photographs.txt', true); await add('A very long filename that should remain readable and never push the transfer controls off the screen.txt', false, false);
  await page.goto(url);
  await expect(page.locator('.row')).toHaveCount(3);
  await row(page, 'Ubuntu installation notes.txt').locator('.rn').click();
  await expect(row(page, 'Ubuntu installation notes.txt').getByRole('tabpanel')).toBeVisible();
  await page.screenshot({path: 'output/playwright/desktop.png', fullPage: true});
  expect(await axe(page)).toEqual([]);
  await page.getByRole('button', {name: 'Toggle theme'}).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.screenshot({path: 'output/playwright/dark.png', fullPage: true});
  expect(await axe(page)).toEqual([]);
  for (const view of ['Search', 'RSS', 'Settings']) {
    await page.getByRole('button', {name: new RegExp('^' + view)}).click();
    await expect(page.locator(`#v-${view.toLowerCase()}`)).toBeVisible();
    expect(await axe(page)).toEqual([]);
  }
  await page.getByRole('button', {name: /^All/}).click();
  await page.setViewportSize({width: 390, height: 844});
  await page.screenshot({path: 'output/playwright/mobile.png', fullPage: true});
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  const box = await row(page, 'A very long filename').getByRole('button', {name: 'Remove', exact: true}).boundingBox();
  expect(box.x + box.width).toBeLessThanOrEqual(390);
  await page.getByRole('button', {name: 'Add', exact: true}).click();
  expect(await axe(page)).toEqual([]);
  await page.keyboard.press('Escape');
  await page.setViewportSize({width: 1280, height: 850});
  await page.getByRole('button', {name: 'Toggle theme'}).click();
  await row(page, 'Archive of photographs.txt').getByRole('button', {name: 'Remove', exact: true}).click();
  expect(await axe(page)).toEqual([]);
  expect(errors).toEqual([]);
});
