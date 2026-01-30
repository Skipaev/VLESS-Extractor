import base64
import json
import hashlib
import platform
from urllib.parse import urlencode, parse_qs, quote, unquote
import requests
from typing import List, Dict, Optional
import urllib3

# Отключаем предупреждения о SSL (для ignore_ssl режима)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DeviceDetailsHelper:
    """Генерация HWID на основе характеристик устройства (как в Throne)"""

    @staticmethod
    def get_device_details() -> Dict[str, str]:
        data = (
                platform.node() +
                platform.processor() +
                platform.system() +
                platform.version()
        ).encode('utf-8')
        hwid = hashlib.sha256(data).hexdigest()[:32]

        return {
            "hwid": hwid,
            "os": platform.system(),
            "os_version": platform.version(),
            "model": platform.machine(),
            "arch": platform.architecture()[0]
        }


class VLESSLinkGenerator:
    """Генератор чистых VLESS ссылок"""

    @staticmethod
    def generate(uuid: str, server: str, port: int,
                 security: str = "none",
                 transport_type: str = "tcp",
                 flow: str = "",
                 sni: str = "",
                 fp: str = "",
                 alpn: str = "",
                 pbk: str = "",
                 sid: str = "",
                 path: str = "",
                 host: str = "",
                 name: str = "",
                 **extra) -> str:
        """
        Генерирует VLESS URL в правильном формате:
        vless://uuid@server:port?params#name
        """
        if not uuid or not server:
            return ""

        params = {
            "encryption": "none",
            "type": transport_type or "tcp"
        }

        # Безопасность
        if security and security != "none":
            params["security"] = security

        # Flow (для XTLS)
        if flow:
            params["flow"] = flow

        # TLS параметры
        if sni:
            params["sni"] = sni
        if fp:
            params["fp"] = fp
        if alpn:
            params["alpn"] = alpn

        # Reality параметры
        if pbk:
            params["pbk"] = pbk
        if sid:
            params["sid"] = sid

        # WebSocket/gRPC параметры
        if path:
            params["path"] = path
        if host:
            params["host"] = host

        query = urlencode(params)
        encoded_name = quote(name, safe='') if name else ""

        url = f"vless://{uuid}@{server}:{port}?{query}"
        if encoded_name:
            url += f"#{encoded_name}"

        return url


class SubscriptionProcessor:
    """Обработчик подписок с поддержкой HWID (совместимо с Throne)"""

    def __init__(self,
                 send_hwid: bool = True,
                 user_agent: str = "",
                 custom_hwid_params: str = "",
                 ignore_ssl: bool = False):
        """
        Args:
            send_hwid: Отправлять ли HWID заголовки
            user_agent: Кастомный User-Agent (пустой = дефолтный Throne-стиль)
            custom_hwid_params: Кастомные HWID параметры в формате "hwid=abc,os=Win"
            ignore_ssl: Игнорировать SSL ошибки (как net_insecure в Throne)
        """
        self.send_hwid = send_hwid
        self.user_agent = user_agent
        self.custom_hwid_params = custom_hwid_params
        self.ignore_ssl = ignore_ssl
        self.device_info = DeviceDetailsHelper.get_device_details()
        self.subscription_userinfo = ""  # Для хранения информации о подписке

    def fetch_subscription(self, url: str) -> str:
        """Загружает подписку с сервера (Throne-совместимые заголовки)"""

        # Дефолтный UA как в Throne
        default_ua = f"Throne/1.0 ({self.device_info['os']}; {self.device_info['arch']})"

        headers = {
            "User-Agent": self.user_agent or default_ua
        }

        if self.send_hwid:
            # Парсим кастомные параметры, как в Throne (sub_custom_hwid_params)
            custom_params = {}
            if self.custom_hwid_params:
                pairs = self.custom_hwid_params.split(',')
                for pair in pairs:
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        key = key.strip().lower()
                        value = value.strip()
                        # Валидация как в Throne
                        if key in ['hwid', 'os', 'osversion', 'model'] and len(value) < 1000:
                            custom_params[key] = value

            # Используем кастомные или дефолтные значения
            hwid = custom_params.get('hwid', self.device_info['hwid'])
            os_ = custom_params.get('os', self.device_info['os'])
            os_version = custom_params.get('osversion', self.device_info['os_version'])
            model = custom_params.get('model', self.device_info['model'])

            # Throne-стиль заголовки с маленькими буквами (КРИТИЧНО!)
            headers.update({
                "x-hwid": hwid,
                "x-device-os": os_,
                "x-ver-os": os_version,
                "x-device-model": model
            })

            print(f"   HWID: {hwid[:16]}...")

        # Запрос с опцией игнорирования SSL (как net_insecure в Throne)
        response = requests.get(
            url,
            headers=headers,
            timeout=20,
            verify=not self.ignore_ssl
        )
        response.raise_for_status()

        # Обработка Subscription-Userinfo (трафик/expire из Throne)
        sub_userinfo = response.headers.get("Subscription-Userinfo", "")
        if sub_userinfo:
            self.subscription_userinfo = sub_userinfo
            print(f"   📊 Subscription-Userinfo: {sub_userinfo}")

        # Проверяем другие полезные заголовки
        profile_title = response.headers.get("Profile-Title", "")
        if profile_title:
            try:
                # Может быть base64
                decoded_title = base64.b64decode(profile_title).decode('utf-8')
                print(f"   📌 Profile: {decoded_title}")
            except:
                print(f"   📌 Profile: {profile_title}")

        return response.text

    def _safe_b64decode(self, data: str) -> str:
        """Безопасное декодирование Base64 (как в Throne - убираем все whitespace)"""
        # Убираем ВСЁ лишнее, как в Throne
        data = data.strip().replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')

        # URL-safe base64 преобразование
        data = data.replace('-', '+').replace('_', '/')

        # Добавляем padding
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding

        try:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except Exception:
            return ""

    def decode_content(self, content: str) -> List[str]:
        """Декодирует содержимое подписки"""
        content = content.strip()

        # Проверяем, это уже ссылки или base64
        protocols = ["vless://", "vmess://", "ss://", "trojan://", "ssr://", "hysteria://", "hy2://"]

        if any(content.startswith(p) for p in protocols):
            # Уже декодировано
            return [l.strip() for l in content.splitlines() if l.strip()]

        # Пробуем base64
        decoded = self._safe_b64decode(content)
        if decoded and any(p in decoded for p in protocols):
            return [l.strip() for l in decoded.splitlines() if l.strip()]

        # Может быть JSON (проверим в process)
        if content.startswith('{') or content.startswith('['):
            return [content]

        return []

    def parse_vless(self, link: str) -> Optional[Dict]:
        """Парсит VLESS ссылку"""
        if not link.startswith("vless://"):
            return None

        try:
            # Убираем протокол
            rest = link[8:]

            # Разделяем по # для получения имени
            name = ""
            if '#' in rest:
                rest, name = rest.rsplit('#', 1)
                name = unquote(name)

            # Разделяем по ? для параметров
            params_str = ""
            if '?' in rest:
                rest, params_str = rest.split('?', 1)

            # UUID@server:port
            if '@' not in rest:
                return None

            uuid, server_port = rest.split('@', 1)

            if ':' in server_port:
                server, port = server_port.rsplit(':', 1)
                port = int(port)
            else:
                server = server_port
                port = 443

            # Парсим параметры
            params = parse_qs(params_str)

            return {
                "uuid": uuid,
                "server": server,
                "port": port,
                "security": params.get("security", ["none"])[0],
                "transport_type": params.get("type", ["tcp"])[0],
                "flow": params.get("flow", [""])[0],
                "sni": params.get("sni", [""])[0],
                "fp": params.get("fp", [""])[0],
                "alpn": params.get("alpn", [""])[0],
                "pbk": params.get("pbk", [""])[0],
                "sid": params.get("sid", [""])[0],
                "path": params.get("path", [""])[0],
                "host": params.get("host", [""])[0],
                "name": name
            }
        except Exception as e:
            print(f"   ⚠️ Ошибка парсинга VLESS: {e}")
            return None

    def parse_vmess(self, link: str) -> Optional[Dict]:
        """Парсит VMess ссылку и конвертирует в формат VLESS"""
        if not link.startswith("vmess://"):
            return None

        try:
            b64_data = link[8:]
            decoded = self._safe_b64decode(b64_data)
            if not decoded:
                return None

            data = json.loads(decoded)

            # Определяем security
            tls = data.get("tls", "")
            if tls in ["tls", "xtls", True, "true", "1"]:
                security = "tls"
            elif tls == "reality":
                security = "reality"
            else:
                security = "none"

            return {
                "uuid": data.get("id", ""),
                "server": data.get("add", ""),
                "port": int(data.get("port", 443)),
                "security": security,
                "transport_type": data.get("net", "tcp"),
                "flow": data.get("flow", ""),
                "sni": data.get("sni", data.get("host", "")),
                "fp": data.get("fp", ""),
                "alpn": data.get("alpn", ""),
                "path": data.get("path", ""),
                "host": data.get("host", ""),
                "name": data.get("ps", ""),
                "pbk": "",
                "sid": ""
            }
        except Exception as e:
            print(f"   ⚠️ Ошибка парсинга VMess: {e}")
            return None

    def parse_singbox_vless(self, out: Dict) -> Optional[Dict]:
        """Парсит sing-box outbound VLESS (как updateSingBox в Throne)"""
        try:
            tls_config = out.get("tls", {})
            transport_config = out.get("transport", {})

            # Определяем security
            if tls_config.get("enabled", False):
                if tls_config.get("reality", {}).get("enabled", False):
                    security = "reality"
                else:
                    security = "tls"
            else:
                security = "none"

            # ALPN может быть списком
            alpn = tls_config.get("alpn", [])
            if isinstance(alpn, list):
                alpn = ','.join(alpn)

            return {
                "uuid": out.get("uuid", ""),
                "server": out.get("server", ""),
                "port": int(out.get("server_port", 443)),
                "security": security,
                "transport_type": transport_config.get("type", "tcp"),
                "flow": out.get("flow", ""),
                "sni": tls_config.get("server_name", ""),
                "fp": tls_config.get("utls", {}).get("fingerprint", ""),
                "alpn": alpn,
                "pbk": tls_config.get("reality", {}).get("public_key", ""),
                "sid": tls_config.get("reality", {}).get("short_id", ""),
                "path": transport_config.get("path", ""),
                "host": transport_config.get("headers", {}).get("Host", ""),
                "name": out.get("tag", "")
            }
        except Exception as e:
            print(f"   ⚠️ Ошибка парсинга sing-box VLESS: {e}")
            return None

    def parse_singbox_vmess(self, out: Dict) -> Optional[Dict]:
        """Парсит sing-box outbound VMess"""
        try:
            tls_config = out.get("tls", {})
            transport_config = out.get("transport", {})

            security = "tls" if tls_config.get("enabled", False) else "none"

            alpn = tls_config.get("alpn", [])
            if isinstance(alpn, list):
                alpn = ','.join(alpn)

            return {
                "uuid": out.get("uuid", ""),
                "server": out.get("server", ""),
                "port": int(out.get("server_port", 443)),
                "security": security,
                "transport_type": transport_config.get("type", "tcp"),
                "flow": "",
                "sni": tls_config.get("server_name", ""),
                "fp": tls_config.get("utls", {}).get("fingerprint", ""),
                "alpn": alpn,
                "pbk": "",
                "sid": "",
                "path": transport_config.get("path", ""),
                "host": transport_config.get("headers", {}).get("Host", ""),
                "name": out.get("tag", "")
            }
        except Exception as e:
            print(f"   ⚠️ Ошибка парсинга sing-box VMess: {e}")
            return None

    def process(self, url: str) -> List[str]:
        """Основной метод обработки подписки"""
        print(f"\n🔄 Загрузка подписки...")

        content = self.fetch_subscription(url)
        print(f"   Получено {len(content)} байт")

        vless_links = []
        stats = {"vless": 0, "vmess": 0, "singbox": 0, "skipped": 0, "failed": 0}

        # Проверяем на sing-box JSON (как updateSingBox в Throne)
        try:
            data = json.loads(content)
            if isinstance(data, dict) and ("outbounds" in data or "endpoints" in data):
                print("   📦 Обнаружен sing-box JSON формат")
                outbounds = data.get("outbounds", []) + data.get("endpoints", [])

                for out in outbounds:
                    out_type = out.get("type", "")

                    if out_type == "vless":
                        parsed = self.parse_singbox_vless(out)
                        if parsed and parsed.get("uuid") and parsed.get("server"):
                            vless_link = VLESSLinkGenerator.generate(**parsed)
                            if vless_link:
                                vless_links.append(vless_link)
                                stats["singbox"] += 1

                    elif out_type == "vmess":
                        parsed = self.parse_singbox_vmess(out)
                        if parsed and parsed.get("uuid") and parsed.get("server"):
                            vless_link = VLESSLinkGenerator.generate(**parsed)
                            if vless_link:
                                vless_links.append(vless_link)
                                stats["singbox"] += 1

                    elif out_type in ["selector", "urltest", "direct", "block", "dns"]:
                        # Служебные типы - пропускаем молча
                        pass

                    else:
                        stats["skipped"] += 1

                print(f"\n📊 Статистика (sing-box):")
                print(f"   Обработано: {stats['singbox']} | Пропущено: {stats['skipped']}")
                return vless_links

        except json.JSONDecodeError:
            pass  # Не JSON, продолжаем как обычно

        # Стандартная обработка ссылок
        links = self.decode_content(content)
        print(f"   Найдено {len(links)} записей")

        for link in links:
            link = link.strip()
            parsed = None

            if link.startswith("vless://"):
                parsed = self.parse_vless(link)
                if parsed:
                    stats["vless"] += 1

            elif link.startswith("vmess://"):
                parsed = self.parse_vmess(link)
                if parsed:
                    stats["vmess"] += 1

            elif link.startswith("trojan://"):
                # Throne пропускает неподдерживаемые типы
                print(f"   ⚠️ Trojan пропущен (нельзя конвертировать в VLESS): {link[:50]}...")
                stats["skipped"] += 1
                continue

            elif link.startswith(("ss://", "ssr://", "hysteria://", "hy2://")):
                # Другие протоколы тоже пропускаем
                protocol = link.split("://")[0]
                print(f"   ⚠️ {protocol.upper()} пропущен (не поддерживается): {link[:50]}...")
                stats["skipped"] += 1
                continue

            else:
                stats["skipped"] += 1
                continue

            if parsed and parsed.get("uuid") and parsed.get("server"):
                vless_link = VLESSLinkGenerator.generate(**parsed)
                if vless_link:
                    vless_links.append(vless_link)
            else:
                stats["failed"] += 1

        print(f"\n📊 Статистика:")
        print(f"   VLESS: {stats['vless']} | VMess→VLESS: {stats['vmess']}")
        print(f"   Пропущено: {stats['skipped']} | Ошибок: {stats['failed']}")

        return vless_links

    def get_subscription_info(self) -> Dict[str, str]:
        """Парсит Subscription-Userinfo в удобный формат"""
        info = {}
        if not self.subscription_userinfo:
            return info

        for part in self.subscription_userinfo.split(';'):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                info[key.strip()] = value.strip()

        return info


def format_bytes(b: int) -> str:
    """Форматирует байты в читаемый формат"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"


def main():
    print("=" * 60)
    print("   🔗 VLESS Link Extractor (Throne-совместимый)")
    print("=" * 60)

    # Показываем информацию об устройстве
    device = DeviceDetailsHelper.get_device_details()
    print(f"\n💻 Устройство: {device['os']} {device['arch']}")
    print(f"🔑 HWID: {device['hwid']}")

    # Ввод URL
    url = input("\n📎 Введите URL подписки: ").strip()

    if not url:
        print("❌ URL пустой!")
        return

    if not url.startswith(('http://', 'https://')):
        print("❌ Неверный формат URL!")
        return

    # Опциональные настройки
    print("\n⚙️ Настройки (Enter для значений по умолчанию):")

    user_agent = input("   User-Agent [Throne/1.0]: ").strip()
    custom_hwid = input("   Кастомный HWID (формат: hwid=xxx,os=Win) [нет]: ").strip()
    ignore_ssl_input = input("   Игнорировать SSL ошибки? (y/n) [n]: ").strip().lower()
    ignore_ssl = ignore_ssl_input == 'y'

    processor = SubscriptionProcessor(
        send_hwid=True,
        user_agent=user_agent,
        custom_hwid_params=custom_hwid,
        ignore_ssl=ignore_ssl
    )

    try:
        vless_links = processor.process(url)

        # Показываем информацию о подписке если есть
        sub_info = processor.get_subscription_info()
        if sub_info:
            print("\n📊 Информация о подписке:")
            if 'upload' in sub_info:
                print(f"   ⬆️ Загружено: {format_bytes(int(sub_info['upload']))}")
            if 'download' in sub_info:
                print(f"   ⬇️ Скачано: {format_bytes(int(sub_info['download']))}")
            if 'total' in sub_info:
                print(f"   📦 Всего: {format_bytes(int(sub_info['total']))}")
            if 'expire' in sub_info:
                from datetime import datetime
                expire_ts = int(sub_info['expire'])
                expire_date = datetime.fromtimestamp(expire_ts)
                print(f"   ⏰ Истекает: {expire_date.strftime('%Y-%m-%d %H:%M')}")

        if not vless_links:
            print("\n⚠️ VLESS ссылки не найдены")
            return

        print("\n" + "=" * 60)
        print("   ✅ РЕЗУЛЬТАТ")
        print("=" * 60)

        for i, link in enumerate(vless_links, 1):
            # Показываем укороченно для читаемости
            if len(link) > 100:
                display = link[:80] + "..." + link[-20:]
            else:
                display = link
            print(f"\n[{i}] {display}")

        print(f"\n📊 Всего: {len(vless_links)} ссылок")

        # Меню действий
        print("\n📋 Действия:")
        print("   1 - Показать полные ссылки")
        print("   2 - Сохранить в файл")
        print("   3 - Скопировать все в буфер")
        print("   4 - Сохранить как base64")
        print("   0 - Выход")

        while True:
            choice = input("\nВыбор: ").strip()

            if choice == "1":
                print("\n" + "-" * 60)
                for i, link in enumerate(vless_links, 1):
                    print(f"\n[{i}]\n{link}")
                print("-" * 60)

            elif choice == "2":
                filename = input("Имя файла (Enter = vless_links.txt): ").strip()
                filename = filename or "vless_links.txt"
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("\n".join(vless_links))
                print(f"✅ Сохранено в {filename}")

            elif choice == "3":
                try:
                    import pyperclip
                    pyperclip.copy("\n".join(vless_links))
                    print("✅ Скопировано в буфер обмена!")
                except ImportError:
                    print("⚠️ Установите pyperclip: pip install pyperclip")
                except Exception as e:
                    print(f"❌ Ошибка: {e}")

            elif choice == "4":
                filename = input("Имя файла (Enter = vless_b64.txt): ").strip()
                filename = filename or "vless_b64.txt"
                b64_content = base64.b64encode("\n".join(vless_links).encode()).decode()
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(b64_content)
                print(f"✅ Сохранено в {filename} (base64)")

            elif choice == "0":
                print("👋 До свидания!")
                break

    except requests.exceptions.SSLError as e:
        print(f"\n❌ SSL ошибка: {e}")
        print("   Попробуйте с опцией 'Игнорировать SSL ошибки = y'")
    except requests.exceptions.ConnectionError:
        print("\n❌ Ошибка подключения. Проверьте интернет.")
    except requests.exceptions.Timeout:
        print("\n❌ Таймаут. Сервер не отвечает.")
    except requests.exceptions.HTTPError as e:
        print(f"\n❌ HTTP ошибка: {e.response.status_code}")
        if e.response.status_code == 403:
            print("   Возможно сервер заблокировал ваш HWID или IP")
        elif e.response.status_code == 404:
            print("   Подписка не найдена или истекла")
    except Exception as e:
        print(f"\n❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()