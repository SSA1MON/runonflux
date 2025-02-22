import requests
import re
import ipaddress
import json
import urllib.parse
import webbrowser
from loguru import logger
import os
from dotenv import load_dotenv
from typing import List, Tuple, Optional


# Загружаем переменные из .env файла
load_dotenv()

FLUX_API_URL = "https://api.runonflux.io"
FLUX_ID = os.getenv("FLUX_ID")
APP_NAME = os.getenv("APP_NAME")
EXTERNAL_API_URL = os.getenv("EXTERNAL_API_URL")


def extract_ips(data: dict) -> List[Tuple[str, str]]:
    """
    Извлекает IP-адреса из ответа API.

    :param data: JSON-данные с сервера
    :return: Список кортежей (IP, порт)
    """
    ip_list = []

    for entry in data.get("data", []):
        ip = entry.get("ip")
        if ip:
            match = re.match(r"([\d.]+)(?::(\d+))?", ip)  # Проверяем, есть ли порт
            if match:
                ip_address = match.group(1)
                port = match.group(2) if match.group(2) else "16127"  # Если порт не указан, устанавливаем стандартный
                ip_list.append((ip_address, port))

    return ip_list


def log_response(response: requests.Response, server_name: str) -> None:
    """
    Логирует ответ от сервера.

    :param response: Ответ от сервера
    :param server_name: Название сервера для контекста
    """
    logger.debug(f"Ответ от сервера {server_name} - Статус: {response.status_code}")
    logger.debug(f"Ответ от сервера {server_name} - Тело ответа: {response.text}")


def get_app_location() -> List[Tuple[str, str]]:
    """
    Запрашивает данные о местоположении приложения и возвращает список IP-адресов.
    """
    params = {"appname": APP_NAME}
    try:
        response = requests.get(f"{FLUX_API_URL}/apps/location", params=params)
        log_response(response, "API Flux")
        response.raise_for_status()
        response_data = response.json()
        ip_list = extract_ips(response_data)
        return ip_list  # Возвращаем список кортежей (IP, порт)
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка запроса к API Flux: {e}")
    except requests.exceptions.JSONDecodeError:
        logger.error("Ошибка: не удалось распарсить JSON из ответа API Flux")
    except Exception as e:
        logger.error(f"Произошла ошибка: {e}")
    return []


def get_external_data() -> List[str]:
    """
    Получает данные из внешнего источника и возвращает список IP-адресов черного списка.
    """
    try:
        response = requests.get(EXTERNAL_API_URL)
        log_response(response, "Внешний API (Черный список)")
        response.raise_for_status()
        response_data = response.json()

        if 'blacklist' in response_data:
            return response_data['blacklist']
        else:
            logger.error("Ошибка: ключ 'blacklist' не найден в данных.")
            return []
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка запроса к внешнему API: {e}")
    except requests.exceptions.JSONDecodeError:
        logger.error("Ошибка: не удалось распарсить JSON из ответа внешнего API")
    except Exception as e:
        logger.error(f"Произошла ошибка: {e}")
    return []


def is_ip_in_blacklist(ip: str, blacklist: List[str]) -> bool:
    """
    Проверяет, является ли IP-адрес в черном списке или попадает ли в одну из сетей с маской.

    :param ip: IP-адрес для проверки
    :param blacklist: Список IP-адресов и сетей в черном списке
    :return: True, если IP в черном списке, иначе False
    """
    for entry in blacklist:
        try:
            if '/' in entry:  # Маска подсети
                network = ipaddress.ip_network(entry, strict=False)
                if ipaddress.ip_address(ip) in network:
                    return True
            elif ip == entry:  # Точное совпадение IP
                return True
        except ValueError:
            continue
    return False


def remove_app(loginphrase: str, signature: str, app_ip: str, port: int = 16127) -> None:
    """Удаляет приложение через GET запрос."""

    # Преобразуем значения в LF (URL-encoded)
    def utf8_to_LF(value: str) -> str:
        return urllib.parse.quote(value)

    # Перекодируем данные
    encoded_flux_id = utf8_to_LF(FLUX_ID)
    encoded_signature = utf8_to_LF(signature)
    encoded_loginphrase = utf8_to_LF(loginphrase)

    # Формируем URL для удаления приложения, используя IP адрес из аргумента
    url = f"http://{app_ip}:{port}/apps/appremove/{APP_NAME}/true/false"
    headers = {
        "zelidauth": f"zelid={encoded_flux_id}&signature={encoded_signature}&loginPhrase={encoded_loginphrase}"
    }

    try:
        response = requests.get(url, headers=headers)
        log_response(response, f"Удаление приложения с IP: {app_ip}, порт: {port}")
        if response.status_code == 200:
            logger.info(f"Приложение {APP_NAME} успешно удалено с {app_ip}:{port}")
        else:
            logger.error(
                f"Ошибка удаления приложения с {app_ip}:{port}. Код ответа: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка запроса к API удаления приложения: {e}")


def get_loginphrase() -> Optional[str]:
    """Получает loginphrase для авторизации."""
    url = f"{FLUX_API_URL}/id/loginphrase"
    try:
        response = requests.get(url)
        log_response(response, "API Flux (loginphrase)")
        return response.json().get("data") if response.status_code == 200 else None
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка запроса к API для получения loginphrase: {e}")
    return None


def open_zelcore_signature(loginphrase: str) -> None:
    """Открывает Zelcore для подписи loginphrase."""
    encoded_message = urllib.parse.quote(loginphrase)
    sign_url = (
        f"zel:?action=sign&message={encoded_message}"
        f"&icon=https%3A//raw.githubusercontent.com/runonflux/flux/master/zelID.svg"
    )
    webbrowser.open(sign_url)


def provide_signature(loginphrase: str, signature: str) -> bool:
    """Подтверждает подпись через API providesign."""
    url = f"{FLUX_API_URL}/id/providesign"
    payload = json.dumps({"address": FLUX_ID, "message": loginphrase, "signature": signature})
    headers = {"Content-Type": "text/plain"}
    try:
        response = requests.post(url, data=payload, headers=headers)
        log_response(response, "API Flux (providesign)")
        return response.status_code == 200 and response.json().get("status") == "success"
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка запроса для подтверждения подписи: {e}")
    return False


def verify_login(loginphrase: str, signature: str) -> Optional[dict]:
    """Подтверждает логин через API verifylogin."""
    url = f"{FLUX_API_URL}/id/verifylogin"
    payload = json.dumps({"loginPhrase": loginphrase, "zelid": FLUX_ID, "signature": signature})
    headers = {"Content-Type": "text/plain"}
    try:
        response = requests.post(url, data=payload, headers=headers)
        log_response(response, "API Flux (verifylogin)")
        if response.status_code == 200:
            response_data = response.json()
            return response_data["data"] if response_data.get("status") == "success" else None
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка запроса для подтверждения логина: {e}")
    return None


def authenticate() -> Tuple[Optional[str], Optional[str]]:
    """
    Процесс аутентификации пользователя через Zelcore.
    """
    loginphrase = get_loginphrase()
    if not loginphrase:
        logger.error("Ошибка получения loginphrase")
        return None, None

    open_zelcore_signature(loginphrase)
    signature = input("Введите полученную подпись: ").strip()
    if not provide_signature(loginphrase, signature):
        logger.error("Ошибка подтверждения подписи")
        return None, None

    login_data = verify_login(loginphrase, signature)
    if not login_data:
        logger.error("Ошибка авторизации")
        return None, None

    return loginphrase, signature


def compare_and_remove() -> None:
    """
    Сравнивает IP-адреса из приложения с черным списком и инициирует удаление приложения, если IP совпали.
    """
    app_ips = get_app_location()
    blacklist = get_external_data()

    if not app_ips:
        logger.info("IP-адреса приложения не найдены.")
        return
    if not blacklist:
        logger.info("Черный список не найден.")
        return

    invalid_ips = []

    for app_ip, app_port in app_ips:
        if is_ip_in_blacklist(app_ip, blacklist):
            invalid_ips.append(f"{app_ip}:{app_port}")

    if invalid_ips:
        logger.info(f"Найдены совпадения с черным списком: {', '.join(invalid_ips)}")
        loginphrase, signature = authenticate()

        if loginphrase and signature:
            for ip in invalid_ips:
                ip_address, port = ip.split(":")
                logger.debug(f"Извлечен IP: {ip_address}, Порт: {port}")
                remove_app(loginphrase, signature, ip_address, port)
            logger.info(f"Общее количество удаленных приложений: {len(invalid_ips)}")
    else:
        logger.info("Совпадений с черным списком не найдено.")


if __name__ == "__main__":
    logger.add("logs/{time:YYYY-MM-DD}.log", rotation="00:00", compression="zip")  # Логи сохраняются и перезаписываются каждый день
    compare_and_remove()
