#!/bin/bash

set -e

# ============================================================
# SSH HARDENING
# ============================================================

clear

echo "========================================="
echo "          SSH HARDENING SETUP"
echo "========================================="
echo ""

# ============================================================
# 1. Ввод всех параметров
# ============================================================

read -rp "Имя главного SSH-пользователя: " SSH_USER

if [[ -z "$SSH_USER" ]]; then
    echo "[ERROR] Имя пользователя не может быть пустым."
    exit 1
fi

# Имя пользователя — только стандартный Linux-вариант
if ! [[ "$SSH_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    echo "[ERROR] Некорректное имя пользователя."
    exit 1
fi


echo ""

read -rp "SSH-порт [Enter = случайный 20000-60000]: " SSH_PORT

if [[ -z "$SSH_PORT" ]]; then
    SSH_PORT=$(shuf -i 20000-60000 -n 1)
fi

if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]]; then
    echo "[ERROR] SSH-порт должен быть числом."
    exit 1
fi

if (( SSH_PORT < 20000 || SSH_PORT > 60000 )); then
    echo "[ERROR] SSH-порт должен быть от 20000 до 60000."
    exit 1
fi


echo ""

read -rp "Ваш публичный SSH-ключ: " PUBLIC_KEY

if [[ -z "$PUBLIC_KEY" ]]; then
    echo "[ERROR] Публичный ключ не может быть пустым."
    exit 1
fi


# ============================================================
# 2. Показываем выбранные настройки
# ============================================================

echo ""
echo "========================================="
echo "          ВЫБРАННЫЕ НАСТРОЙКИ"
echo "========================================="
echo ""
echo "SSH USER : $SSH_USER"
echo "SSH PORT : $SSH_PORT"
echo "SSH KEY  : ${PUBLIC_KEY:0:40}..."
echo ""
echo "Главный конфиг:"
echo "/etc/ssh/sshd_config.d/01-my-settings-ssh.conf"
echo ""
echo "SSH socket override:"
echo "/etc/systemd/system/ssh.socket.d/override.conf"
echo ""

read -rp "Продолжить? [y/N]: " CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Отменено."
    exit 0
fi


# ============================================================
# 3. Проверяем наличие sshd
# ============================================================

echo ""
echo "========================================="
echo "3. Проверка SSH"
echo "========================================="

if ! command -v sshd >/dev/null 2>&1; then
    echo "[ERROR] sshd не найден."
    exit 1
fi

echo "[OK] sshd найден."


# ============================================================
# 4. Проверяем текущие SSH-конфиги
# ============================================================

echo ""
echo "========================================="
echo "4. Текущие SSH-конфиги"
echo "========================================="

echo ""
echo "--- /etc/ssh/sshd_config ---"

if [[ -f /etc/ssh/sshd_config ]]; then
    sudo sed -n '1,240p' /etc/ssh/sshd_config
else
    echo "[WARNING] Файл отсутствует."
fi

echo ""
echo "--- /etc/ssh/sshd_config.d/ ---"

sudo find /etc/ssh/sshd_config.d \
    -maxdepth 1 \
    -type f \
    -printf '%f\n' \
    2>/dev/null | sort || true


# ============================================================
# 5. Проверяем выбранный порт
# ============================================================

echo ""
echo "========================================="
echo "5. Проверка порта $SSH_PORT"
echo "========================================="

if sudo ss -lntup | grep -qE ":${SSH_PORT}\b"; then

    echo "[ERROR] Порт $SSH_PORT уже используется:"
    sudo ss -lntup | grep -E ":${SSH_PORT}\b"

    exit 1

else

    echo "[OK] Порт $SSH_PORT свободен."

fi


# ============================================================
# 6. Создаём пользователя
# ============================================================

echo ""
echo "========================================="
echo "6. Пользователь $SSH_USER"
echo "========================================="

if id "$SSH_USER" >/dev/null 2>&1; then

    echo "[INFO] Пользователь уже существует."

else

    sudo adduser --disabled-password --gecos "" "$SSH_USER"

    echo "[OK] Пользователь создан."

fi

sudo usermod -aG sudo "$SSH_USER"

echo "[OK] Пользователь добавлен в группу sudo."


# ============================================================
# 7. Настраиваем SSH-ключ
# ============================================================

echo ""
echo "========================================="
echo "7. Установка SSH-ключа"
echo "========================================="

sudo mkdir -p "/home/$SSH_USER/.ssh"

echo "$PUBLIC_KEY" | sudo tee \
    "/home/$SSH_USER/.ssh/authorized_keys" > /dev/null

sudo chown -R "$SSH_USER:$SSH_USER" \
    "/home/$SSH_USER/.ssh"

sudo chmod 700 \
    "/home/$SSH_USER/.ssh"

sudo chmod 600 \
    "/home/$SSH_USER/.ssh/authorized_keys"

echo "[OK] SSH-ключ установлен."


# ============================================================
# 8. Создаём главный SSH-конфиг
# ============================================================

echo ""
echo "========================================="
echo "8. Главный SSH-конфиг"
echo "========================================="

SSH_CONFIG="/etc/ssh/sshd_config.d/01-my-settings-ssh.conf"

sudo tee "$SSH_CONFIG" > /dev/null <<EOF
# ============================================================
# My SSH settings
# ============================================================

Port $SSH_PORT

PermitRootLogin no

PasswordAuthentication no

KbdInteractiveAuthentication no

PubkeyAuthentication yes

AllowUsers $SSH_USER
EOF

echo "[OK] Создан:"
echo "$SSH_CONFIG"


# ============================================================
# 9. Проверяем синтаксис SSH
# ============================================================

echo ""
echo "========================================="
echo "9. Проверка синтаксиса sshd"
echo "========================================="

sudo sshd -t

echo "[OK] SSH-конфигурация синтаксически корректна."


# ============================================================
# 10. Показываем порядок конфигов
# ============================================================

echo ""
echo "========================================="
echo "10. Порядок SSH-конфигов"
echo "========================================="

sudo find /etc/ssh/sshd_config.d \
    -maxdepth 1 \
    -type f \
    -printf '%f\n' \
    2>/dev/null | sort


# ============================================================
# 11. Показываем наш конфиг
# ============================================================

echo ""
echo "========================================="
echo "11. Наш главный конфиг"
echo "========================================="

sudo cat "$SSH_CONFIG"


# ============================================================
# 12. Проверяем эффективный конфиг
# ============================================================

echo ""
echo "========================================="
echo "12. Эффективные настройки sshd"
echo "========================================="

sudo sshd -T | grep -E \
'^(port|listenaddress|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|allowusers|authorizedkeysfile) '


# ============================================================
# 13. Проверяем эффективные значения
# ============================================================

echo ""
echo "========================================="
echo "13. Проверка параметров"
echo "========================================="

EFFECTIVE_PORT=$(sudo sshd -T | awk '$1=="port"{print $2; exit}')
EFFECTIVE_ROOT=$(sudo sshd -T | awk '$1=="permitrootlogin"{print $2}')
EFFECTIVE_PASSWORD=$(sudo sshd -T | awk '$1=="passwordauthentication"{print $2}')
EFFECTIVE_INTERACTIVE=$(sudo sshd -T | awk '$1=="kbdinteractiveauthentication"{print $2}')
EFFECTIVE_PUBKEY=$(sudo sshd -T | awk '$1=="pubkeyauthentication"{print $2}')
EFFECTIVE_USER=$(sudo sshd -T | awk '$1=="allowusers"{print $2}')


if [[ "$EFFECTIVE_PORT" == "$SSH_PORT" ]]; then
    echo "[OK] SSH port: $SSH_PORT"
else
    echo "[ERROR] SSH использует порт $EFFECTIVE_PORT вместо $SSH_PORT."
    exit 1
fi


if [[ "$EFFECTIVE_ROOT" == "no" ]]; then
    echo "[OK] Root login: disabled"
else
    echo "[ERROR] Root login НЕ отключён."
    exit 1
fi


if [[ "$EFFECTIVE_PASSWORD" == "no" ]]; then
    echo "[OK] Password login: disabled"
else
    echo "[ERROR] Password login НЕ отключён."
    exit 1
fi


if [[ "$EFFECTIVE_INTERACTIVE" == "no" ]]; then
    echo "[OK] Keyboard interactive: disabled"
else
    echo "[ERROR] Keyboard interactive НЕ отключён."
    exit 1
fi


if [[ "$EFFECTIVE_PUBKEY" == "yes" ]]; then
    echo "[OK] Public key authentication: enabled"
else
    echo "[ERROR] Public key authentication отключён."
    exit 1
fi


if [[ "$EFFECTIVE_USER" == "$SSH_USER" ]]; then
    echo "[OK] AllowUsers: $SSH_USER"
else
    echo "[ERROR] AllowUsers настроен неправильно."
    exit 1
fi


# ============================================================
# 14. Настраиваем systemd ssh.socket
# ============================================================

echo ""
echo "========================================="
echo "14. Настройка systemd ssh.socket"
echo "========================================="

if systemctl list-unit-files | grep -q '^ssh.socket'; then

    echo "[INFO] ssh.socket найден."

    sudo mkdir -p /etc/systemd/system/ssh.socket.d

    sudo tee \
        /etc/systemd/system/ssh.socket.d/override.conf > /dev/null <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:$SSH_PORT
ListenStream=[::]:$SSH_PORT
EOF

    echo "[OK] Создан:"
    echo "/etc/systemd/system/ssh.socket.d/override.conf"

else

    echo "[INFO] ssh.socket не используется."

fi


# ============================================================
# 15. Показываем override.conf
# ============================================================

if [[ -f /etc/systemd/system/ssh.socket.d/override.conf ]]; then

    echo ""
    echo "--- ssh.socket override ---"

    sudo cat /etc/systemd/system/ssh.socket.d/override.conf

fi


# ============================================================
# 16. Перечитываем systemd
# ============================================================

echo ""
echo "========================================="
echo "16. systemd daemon-reload"
echo "========================================="

sudo systemctl daemon-reload

echo "[OK] systemd перечитал конфигурацию."


# ============================================================
# 17. Проверяем ssh.socket ДО перезапуска
# ============================================================

if systemctl list-unit-files | grep -q '^ssh.socket'; then

    echo ""
    echo "========================================="
    echo "17. Проверка ssh.socket"
    echo "========================================="

    sudo systemctl show ssh.socket -p Listen

fi


# ============================================================
# 18. UFW
# ============================================================

echo ""
echo "========================================="
echo "18. Настройка UFW"
echo "========================================="

if sudo ufw status | grep -q "Status: active"; then

    echo "[INFO] UFW активен."

    # --------------------------------------------------------
    # Разрешаем новый SSH-порт
    # --------------------------------------------------------

    if sudo ufw status | grep -qE "^${SSH_PORT}/tcp[[:space:]]+ALLOW"; then
        echo "[OK] Порт $SSH_PORT/tcp уже разрешён в UFW."
    else
        sudo ufw allow "$SSH_PORT/tcp"
        echo "[OK] Разрешён SSH-порт $SSH_PORT/tcp."
    fi


    # --------------------------------------------------------
    # Удаляем старый SSH-порт 22
    # --------------------------------------------------------

    echo ""
    echo "--- Проверка старого правила 22/tcp ---"

    if sudo ufw status | grep -qE '^22/tcp[[:space:]]+ALLOW'; then

        echo "[INFO] Найдено правило 22/tcp."

        sudo ufw delete allow 22/tcp

        echo "[OK] Правило 22/tcp удалено."

    else

        echo "[OK] Правило 22/tcp отсутствует."

    fi


    # --------------------------------------------------------
    # Проверяем, что новый порт разрешён
    # --------------------------------------------------------

    echo ""
    echo "--- Проверка нового SSH-порта в UFW ---"

    if sudo ufw status | grep -qE "^${SSH_PORT}/tcp[[:space:]]+ALLOW"; then

        echo "[OK] UFW разрешает $SSH_PORT/tcp."

    else

        echo "[ERROR] UFW НЕ разрешает $SSH_PORT/tcp."
        sudo ufw status numbered
        exit 1

    fi


    # --------------------------------------------------------
    # Проверяем, что 22 больше не разрешён
    # --------------------------------------------------------

    echo ""
    echo "--- Проверка удаления 22/tcp ---"

    if sudo ufw status | grep -qE '^22/tcp[[:space:]]+ALLOW'; then

        echo "[ERROR] Правило 22/tcp всё ещё существует!"
        sudo ufw status numbered
        exit 1

    else

        echo "[OK] Правило 22/tcp отсутствует."

    fi

else

    echo "[INFO] UFW не активен."
    echo "[INFO] Правила UFW изменяться не будут."

fi

# ============================================================
# 19. Перезапускаем SSH
# ============================================================

echo ""
echo "========================================="
echo "19. Перезапуск SSH"
echo "========================================="

if systemctl list-unit-files | grep -q '^ssh.socket'; then
    sudo systemctl restart ssh.socket
fi

sudo systemctl restart ssh

sleep 2

echo "[OK] SSH перезапущен."


# ============================================================
# 20. Реальные listening ports
# ============================================================

echo ""
echo "========================================="
echo "20. Реально слушаемые SSH-порты"
echo "========================================="

sudo ss -lntp | grep -E ':(22|'"$SSH_PORT"')\b' || true


# ============================================================
# 21. Проверяем порт 22
# ============================================================

echo ""
echo "========================================="
echo "21. Проверка старого порта 22"
echo "========================================="

if sudo ss -lntp | grep -qE ':22\b'; then

    echo "[ERROR] Порт 22 всё ещё слушается!"
    sudo ss -lntp | grep -E ':22\b'

    echo ""
    echo "Проверяем ssh.socket:"
    sudo systemctl show ssh.socket -p Listen

    exit 1

else

    echo "[OK] Порт 22 НЕ слушается."

fi


# ============================================================
# 22. Проверяем новый порт
# ============================================================

echo ""
echo "========================================="
echo "22. Проверка порта $SSH_PORT"
echo "========================================="

if sudo ss -lntp | grep -qE ':'"$SSH_PORT"'\b'; then

    echo "[OK] Порт $SSH_PORT реально слушается."

else

    echo "[ERROR] Порт $SSH_PORT НЕ слушается!"

    echo ""
    echo "--- ssh.service ---"
    sudo systemctl status ssh --no-pager || true

    echo ""
    echo "--- ssh.socket ---"
    sudo systemctl status ssh.socket --no-pager || true

    echo ""
    echo "--- ssh.socket Listen ---"
    sudo systemctl show ssh.socket -p Listen || true

    exit 1

fi


# ============================================================
# 23. Проверяем пользователя
# ============================================================

echo ""
echo "========================================="
echo "23. Проверка пользователя"
echo "========================================="

id "$SSH_USER"

if id -nG "$SSH_USER" | grep -qw sudo; then
    echo "[OK] $SSH_USER имеет sudo."
else
    echo "[ERROR] $SSH_USER НЕ имеет sudo."
    exit 1
fi


# ============================================================
# 24. Проверяем SSH-файлы пользователя
# ============================================================

echo ""
echo "========================================="
echo "24. SSH-файлы пользователя"
echo "========================================="

sudo ls -ld "/home/$SSH_USER/.ssh"
sudo ls -l "/home/$SSH_USER/.ssh/authorized_keys"


if [[ "$(sudo stat -c '%a' "/home/$SSH_USER/.ssh")" == "700" ]]; then
    echo "[OK] .ssh = 700"
else
    echo "[ERROR] Неправильные права .ssh."
    exit 1
fi


if [[ "$(sudo stat -c '%a' "/home/$SSH_USER/.ssh/authorized_keys")" == "600" ]]; then
    echo "[OK] authorized_keys = 600"
else
    echo "[ERROR] Неправильные права authorized_keys."
    exit 1
fi


# ============================================================
# 25. Проверяем authorized_keys
# ============================================================

echo ""
echo "========================================="
echo "25. Проверка authorized_keys"
echo "========================================="

if sudo test -s "/home/$SSH_USER/.ssh/authorized_keys"; then
    echo "[OK] authorized_keys существует и не пуст."
else
    echo "[ERROR] authorized_keys отсутствует или пуст."
    exit 1
fi


# ============================================================
# 26. Финальный UFW
# ============================================================

echo ""
echo "========================================="
echo "26. Текущий UFW"
echo "========================================="

sudo ufw status numbered

# ============================================================
# 26.5 Финальная автоматическая проверка UFW
# ============================================================

echo ""
echo "========================================="
echo "26.5. Финальная проверка UFW"
echo "========================================="

if sudo ufw status | grep -q "Status: active"; then

    if sudo ufw status | grep -qE "^22/tcp[[:space:]]+ALLOW"; then
        echo "[ERROR] UFW всё ещё разрешает 22/tcp!"
        exit 1
    else
        echo "[OK] UFW не разрешает 22/tcp."
    fi

    if sudo ufw status | grep -qE "^${SSH_PORT}/tcp[[:space:]]+ALLOW"; then
        echo "[OK] UFW разрешает $SSH_PORT/tcp."
    else
        echo "[ERROR] UFW НЕ разрешает $SSH_PORT/tcp!"
        exit 1
    fi

else

    echo "[INFO] UFW не активен — проверка правил пропущена."

fi


# ============================================================
# 27. Финальная проверка
# ============================================================

echo ""
echo "========================================="
echo "       SSH SETUP COMPLETED"
echo "========================================="
echo ""
echo "SSH USER       : $SSH_USER"
echo "SSH PORT       : $SSH_PORT"
echo "ROOT LOGIN     : disabled"
echo "PASSWORD LOGIN : disabled"
echo "KEY LOGIN      : enabled"
echo "PORT 22        : disabled"
echo "UFW            : checked"
echo "SSH SOCKET     : checked"
echo ""
echo "Главный SSH-конфиг:"
echo "/etc/ssh/sshd_config.d/01-my-settings-ssh.conf"
echo ""
echo "SSH socket override:"
echo "/etc/systemd/system/ssh.socket.d/override.conf"
echo ""
echo "========================================="
echo ""
echo "!!! НЕ ЗАКРЫВАЙ ТЕКУЩУЮ SSH-СЕССИЮ !!!"
echo ""
echo "Сначала проверь новое подключение:"
echo ""
echo "ssh -p $SSH_PORT $SSH_USER@IP_СЕРВЕРА"
echo ""
