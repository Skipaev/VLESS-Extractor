import base64
import json
import re
import hashlib
import platform
from urllib.parse import urlencode, parse_qs, quote, unquote
import requests
from typing import List, Dict, Optional
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DeviceDetailsHelper:
    @staticmethod
    def get_device_details() -> dict:
        data = (platform.node() + platform.processor() + platform.system() + platform.version()).encode('utf-8')
        hwid = hashlib.sha256(data).hexdigest()[:32]
        return {
            "hwid": hwid,
            "os": platform.system(),
            "os_version": platform.version(),
            "model": platform.machine(),
            "arch": platform.architecture()[0],
        }


class VLESSLinkGenerator:
    @staticmethod
    def generate(uuid: str, server: str, port: int,
                 security: str = "none", transport_type: str = "tcp",
                 flow: str = "", sni: str = "", fp: str = "", alpn: str = "",
                 pbk: str = "", sid: str = "", path: str = "", host: str = "",
                 name: str = "", **_) -> str:
        if not uuid or not server:
            return ""
        params = {"encryption": "none", "type": transport_type or "tcp"}
        if security and security != "none":
            params["security"] = security
        if flow:   params["flow"] = flow
        if sni:    params["sni"] = sni
        if fp:     params["fp"] = fp
        if alpn:   params["alpn"] = alpn
        if pbk:    params["pbk"] = pbk
        if sid:    params["sid"] = sid
        if path:   params["path"] = path
        if host:   params["host"] = host
        url = f"vless://{uuid}@{server}:{port}?{urlencode(params)}"
        if name:
            url += f"#{quote(name, safe='')}"
        return url


class SubscriptionProcessor:
    def __init__(self, user_agent: str = "", ignore_ssl: bool = False,
                 send_hwid: bool = True, custom_hwid_params: str = ""):
        self.user_agent = user_agent
        self.ignore_ssl = ignore_ssl
        self.send_hwid = send_hwid
        self.custom_hwid_params = custom_hwid_params
        self.device_info = DeviceDetailsHelper.get_device_details()
        self.subscription_userinfo = ""

    def _build_headers(self) -> dict:
        default_ua = f"Throne/1.0 ({self.device_info['os']}; {self.device_info['arch']})"
        headers = {"User-Agent": self.user_agent or default_ua}

        if self.send_hwid:
            custom = {}
            for pair in self.custom_hwid_params.split(','):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    k = k.strip().lower()
                    if k in ('hwid', 'os', 'osversion', 'model') and len(v.strip()) < 1000:
                        custom[k] = v.strip()
            headers.update({
                "x-hwid":         custom.get('hwid',      self.device_info['hwid']),
                "x-device-os":    custom.get('os',        self.device_info['os']),
                "x-ver-os":       custom.get('osversion', self.device_info['os_version']),
                "x-device-model": custom.get('model',     self.device_info['model']),
            })
        return headers

    def fetch_subscription(self, url: str) -> str:
        """Загружает подписку. Если сервер вернул HTML — ищет rawSubscriptionUrl внутри."""
        headers = self._build_headers()
        r = requests.get(url, headers=headers, timeout=20, verify=not self.ignore_ssl)
        r.raise_for_status()

        content_type = r.headers.get("content-type", "")

        # Сервер вернул HTML-страницу — ищем реальный URL подписки в JS
        if "html" in content_type.lower() or r.text.lstrip().startswith("<!"):
            real_url = self._extract_url_from_html(r.text)
            if real_url:
                print(f"   🔍 HTML-страница, найден реальный URL: {real_url}")
                return self.fetch_subscription(real_url)
            else:
                raise ValueError("Получена HTML-страница, но rawSubscriptionUrl не найден")

        sub_userinfo = r.headers.get("Subscription-Userinfo", "")
        if sub_userinfo:
            self.subscription_userinfo = sub_userinfo

        return r.text

    def _extract_url_from_html(self, html: str) -> Optional[str]:
        """Ищет rawSubscriptionUrl или похожие переменные в JS внутри HTML."""
        patterns = [
            r'rawSubscriptionUrl\s*=\s*["\']([^"\']+)["\']',
            r'subscriptionUrl\s*=\s*["\']([^"\']+)["\']',
            r'subUrl\s*=\s*["\']([^"\']+)["\']',
            r'sub_url\s*=\s*["\']([^"\']+)["\']',
        ]
        for pat in patterns:
            m = re.search(pat, html)
            if m:
                url = m.group(1).split('#')[0]  # убираем fragment
                return url
        return None

    def _safe_b64decode(self, data: str) -> str:
        data = data.strip().replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')
        data = data.replace('-', '+').replace('_', '/')
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        try:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except Exception:
            return ""

    def decode_content(self, content: str) -> List[str]:
        content = content.strip()
        protocols = ["vless://", "vmess://", "ss://", "trojan://", "ssr://", "hysteria://", "hy2://"]

        # Фильтруем комментарии (#...) и пустые строки, но сначала проверяем протоколы
        lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith('#')]

        if lines and any(lines[0].startswith(p) for p in protocols):
            return lines

        # Пробуем base64 (берём только непустые не-комментарии)
        raw = ''.join(lines)
        decoded = self._safe_b64decode(raw)
        if decoded and any(p in decoded for p in protocols):
            return [l.strip() for l in decoded.splitlines() if l.strip()]

        if content.startswith('{') or content.startswith('['):
            return [content]

        return []

    def parse_vless(self, link: str) -> Optional[Dict]:
        if not link.startswith("vless://"):
            return None
        try:
            rest = link[8:]
            name = ""
            # Отделяем название: ищем первый # который не внутри значения параметра
            if '#' in rest:
                if '?' in rest:
                    q_pos = rest.index('?')
                    params_part = rest[q_pos:]
                    # Ищем # после последнего &
                    last_amp = params_part.rfind('&')
                    search_from = q_pos + last_amp + 1 if last_amp > 0 else q_pos
                    hash_pos = rest.find('#', search_from)
                    if hash_pos > 0:
                        name = unquote(rest[hash_pos+1:])
                        rest = rest[:hash_pos]
                else:
                    rest, name = rest.split('#', 1)
                    name = unquote(name)
            
            params_str = ""
            if '?' in rest:
                rest, params_str = rest.split('?', 1)
            if '@' not in rest:
                return None
            uuid, server_port = rest.split('@', 1)
            server, port = server_port.rsplit(':', 1)
            params = parse_qs(params_str)
            
            # Очищаем flow от # и текста после него
            flow_raw = params.get("flow", [""])[0]
            if "#" in flow_raw:
                flow_raw = flow_raw.split("#")[0]
            
            return {
                "uuid": uuid, "server": server, "port": int(port),
                "security": params.get("security", ["none"])[0],
                "transport_type": params.get("type", ["tcp"])[0],
                "flow": flow_raw,
                "sni": params.get("sni", [""])[0],
                "fp": params.get("fp", [""])[0],
                "alpn": params.get("alpn", [""])[0],
                "pbk": params.get("pbk", [""])[0],
                "sid": params.get("sid", [""])[0],
                "path": params.get("path", [""])[0],
                "host": params.get("host", [""])[0],
                "name": name,
            }
        except Exception as e:
            print(f"   ⚠️ Ошибка парсинга VLESS: {e}")
            return None

    def parse_vmess(self, link: str) -> Optional[Dict]:
        if not link.startswith("vmess://"):
            return None
        try:
            data = json.loads(self._safe_b64decode(link[8:]))
            tls = data.get("tls", "")
            security = "tls" if tls in ["tls", "xtls", True, "true", "1"] else ("reality" if tls == "reality" else "none")
            return {
                "uuid": data.get("id", ""), "server": data.get("add", ""),
                "port": int(data.get("port", 443)), "security": security,
                "transport_type": data.get("net", "tcp"), "flow": data.get("flow", ""),
                "sni": data.get("sni", data.get("host", "")), "fp": data.get("fp", ""),
                "alpn": data.get("alpn", ""), "path": data.get("path", ""),
                "host": data.get("host", ""), "name": data.get("ps", ""),
                "pbk": "", "sid": "",
            }
        except Exception as e:
            print(f"   ⚠️ Ошибка парсинга VMess: {e}")
            return None

    def parse_singbox_vless(self, out: Dict) -> Optional[Dict]:
        try:
            tls = out.get("tls", {})
            tr = out.get("transport", {})
            if tls.get("enabled"):
                security = "reality" if tls.get("reality", {}).get("enabled") else "tls"
            else:
                security = "none"
            alpn = tls.get("alpn", [])
            return {
                "uuid": out.get("uuid", ""), "server": out.get("server", ""),
                "port": int(out.get("server_port", 443)), "security": security,
                "transport_type": tr.get("type", "tcp"), "flow": out.get("flow", ""),
                "sni": tls.get("server_name", ""), "fp": tls.get("utls", {}).get("fingerprint", ""),
                "alpn": ','.join(alpn) if isinstance(alpn, list) else alpn,
                "pbk": tls.get("reality", {}).get("public_key", ""),
                "sid": tls.get("reality", {}).get("short_id", ""),
                "path": tr.get("path", ""), "host": tr.get("headers", {}).get("Host", ""),
                "name": out.get("tag", ""),
            }
        except Exception as e:
            print(f"   ⚠️ Ошибка парсинга sing-box VLESS: {e}")
            return None

    def parse_singbox_vmess(self, out: Dict) -> Optional[Dict]:
        try:
            tls = out.get("tls", {})
            tr = out.get("transport", {})
            alpn = tls.get("alpn", [])
            return {
                "uuid": out.get("uuid", ""), "server": out.get("server", ""),
                "port": int(out.get("server_port", 443)),
                "security": "tls" if tls.get("enabled") else "none",
                "transport_type": tr.get("type", "tcp"), "flow": "",
                "sni": tls.get("server_name", ""), "fp": tls.get("utls", {}).get("fingerprint", ""),
                "alpn": ','.join(alpn) if isinstance(alpn, list) else alpn,
                "pbk": "", "sid": "",
                "path": tr.get("path", ""), "host": tr.get("headers", {}).get("Host", ""),
                "name": out.get("tag", ""),
            }
        except Exception as e:
            print(f"   ⚠️ Ошибка парсинга sing-box VMess: {e}")
            return None

    def process(self, url: str) -> List[str]:
        print(f"\n🔄 Загрузка подписки...")
        content = self.fetch_subscription(url)
        print(f"   Получено {len(content)} байт")

        vless_links = []
        stats = {"vless": 0, "vmess": 0, "singbox": 0, "skipped": 0, "failed": 0}

        # sing-box JSON
        try:
            data = json.loads(content)
            if isinstance(data, dict) and ("outbounds" in data or "endpoints" in data):
                print("   📦 sing-box JSON")
                for out in data.get("outbounds", []) + data.get("endpoints", []):
                    t = out.get("type", "")
                    parsed = None
                    if t == "vless":
                        parsed = self.parse_singbox_vless(out)
                    elif t == "vmess":
                        parsed = self.parse_singbox_vmess(out)
                    elif t in ("selector", "urltest", "direct", "block", "dns"):
                        continue
                    else:
                        stats["skipped"] += 1
                        continue
                    if parsed and parsed.get("uuid") and parsed.get("server"):
                        link = VLESSLinkGenerator.generate(**parsed)
                        if link:
                            vless_links.append(link)
                            stats["singbox"] += 1
                print(f"   Обработано: {stats['singbox']} | Пропущено: {stats['skipped']}")
                return vless_links
        except json.JSONDecodeError:
            pass

        # Стандартные ссылки
        links = self.decode_content(content)
        print(f"   Найдено {len(links)} записей")

        for link in links:
            parsed = None
            if link.startswith("vless://"):
                parsed = self.parse_vless(link)
                if parsed: stats["vless"] += 1
            elif link.startswith("vmess://"):
                parsed = self.parse_vmess(link)
                if parsed: stats["vmess"] += 1
            else:
                stats["skipped"] += 1
                continue

            if parsed and parsed.get("uuid") and parsed.get("server"):
                link = VLESSLinkGenerator.generate(**parsed)
                if link:
                    vless_links.append(link)
            else:
                stats["failed"] += 1

        print(f"   VLESS: {stats['vless']} | VMess→VLESS: {stats['vmess']} | Пропущено: {stats['skipped']} | Ошибок: {stats['failed']}")
        return vless_links

    def get_subscription_info(self) -> Dict[str, str]:
        info = {}
        for part in self.subscription_userinfo.split(';'):
            part = part.strip()
            if '=' in part:
                k, v = part.split('=', 1)
                info[k.strip()] = v.strip()
        return info


def format_bytes(b: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"


def main():
    print("=" * 60)
    print("   🔗 VLESS Link Extractor")
    print("=" * 60)

    url = input("\n📎 URL подписки: ").strip()
    if not url or not url.startswith(('http://', 'https://')):
        print("❌ Неверный URL")
        return

    print("\n⚙️  Настройки (Enter = по умолчанию):")
    user_agent   = input("   User-Agent [Throne/1.0]: ").strip()
    custom_hwid  = input("   Кастомный HWID (hwid=xxx,os=Win) [нет]: ").strip()
    send_hwid    = input("   Отправлять HWID заголовки? (y/n) [y]: ").strip().lower() != 'n'
    ignore_ssl   = input("   Игнорировать SSL? (y/n) [n]: ").strip().lower() == 'y'

    device = DeviceDetailsHelper.get_device_details()
    print(f"\n💻 OS:      {device['os']} {device['os_version']}")
    print(f"   Arch:    {device['arch']}")
    print(f"   Model:   {device['model']}")
    print(f"   HWID:    {device['hwid']}")

    processor = SubscriptionProcessor(
        user_agent=user_agent,
        ignore_ssl=ignore_ssl,
        send_hwid=send_hwid,
        custom_hwid_params=custom_hwid,
    )

    try:
        vless_links = processor.process(url)

        sub_info = processor.get_subscription_info()
        if sub_info:
            print("\n📊 Подписка:")
            if 'upload' in sub_info:   print(f"   ⬆️  {format_bytes(int(sub_info['upload']))}")
            if 'download' in sub_info: print(f"   ⬇️  {format_bytes(int(sub_info['download']))}")
            if 'total' in sub_info:    print(f"   📦 {format_bytes(int(sub_info['total']))}")
            if 'expire' in sub_info:
                from datetime import datetime
                print(f"   ⏰ {datetime.fromtimestamp(int(sub_info['expire'])).strftime('%Y-%m-%d %H:%M')}")

        if not vless_links:
            print("\n⚠️ VLESS ссылки не найдены")
            return

        print(f"\n✅ Найдено {len(vless_links)} ссылок\n")
        for i, link in enumerate(vless_links, 1):
            display = link[:80] + "..." if len(link) > 80 else link
            print(f"[{i}] {display}")

        print("\n1 - Полные ссылки  2 - Сохранить  3 - Base64  0 - Выход")
        while True:
            choice = input("\nВыбор: ").strip()
            if choice == "1":
                for i, link in enumerate(vless_links, 1):
                    print(f"\n[{i}]\n{link}")
            elif choice == "2":
                fn = input("Файл [vless_links.txt]: ").strip() or "vless_links.txt"
                with open(fn, "w", encoding="utf-8") as f:
                    f.write("\n".join(vless_links))
                print(f"✅ Сохранено в {fn}")
            elif choice == "3":
                fn = input("Файл [vless_b64.txt]: ").strip() or "vless_b64.txt"
                with open(fn, "w", encoding="utf-8") as f:
                    f.write(base64.b64encode("\n".join(vless_links).encode()).decode())
                print(f"✅ Сохранено в {fn}")
            elif choice == "0":
                break

    except requests.exceptions.SSLError:
        print("\n❌ SSL ошибка — попробуй с ignore SSL = y")
    except requests.exceptions.ConnectionError:
        print("\n❌ Нет подключения")
    except requests.exceptions.Timeout:
        print("\n❌ Таймаут")
    except requests.exceptions.HTTPError as e:
        print(f"\n❌ HTTP {e.response.status_code}")
    except ValueError as e:
        print(f"\n❌ {e}")
    except Exception as e:
        import traceback
        print(f"\n❌ {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
