#!/usr/bin/env bash

set -euo pipefail

# ============================================================
# SSH HARDENING SETUP
#
# Базовое усиление безопасности SSH на Ubuntu Server.
#
# Возможности:
# - создание SSH-пользователя;
# - добавление пользователя в sudo;
# - установка публичного SSH-ключа;
# - отключение root login;
# - отключение password authentication;
# - отключение keyboard-interactive;
# - AllowUsers;
# - изменение SSH-порта;
# - настройка systemd ssh.socket;
# - настройка UFW;
# - удаление старого правила 22/tcp;
# - проверки sshd -t / sshd -T;
# - проверка реального listening port;
# - backup с ротацией (хранится 10 последних);
# - резервирование порта при попадании в эфемерный диапазон;
# - автоматический rollback при ошибке;
# - ручной rollback через --rollback.
#
# ВАЖНО:
# Не закрывайте текущую SSH-сессию, пока не проверите
# новое подключение.
# ============================================================


# ============================================================
# 0. PATH
# ============================================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"


# ============================================================
# 1. Константы
# ============================================================

SCRIPT_NAME="$(basename "$0")"

SSH_CONFIG="/etc/ssh/sshd_config.d/01-my-settings-ssh.conf"

SOCKET_DROPIN_DIR="/etc/systemd/system/ssh.socket.d"
SOCKET_DROPIN="$SOCKET_DROPIN_DIR/override.conf"

BACKUP_ROOT="/root/ssh-hardening-backups"
CURRENT_BACKUP="$BACKUP_ROOT/current"
KEEP_BACKUPS=10

SYSCTL_RESERVE_FILE="/etc/sysctl.d/99-ssh-setup-reserved-port.conf"

AUTHORIZED_KEYS=""

SSH_SERVICE="ssh"

if ! systemctl cat ssh.service >/dev/null 2>&1; then
    SSH_SERVICE="sshd"
fi


# ============================================================
# 2. Цвета и функции вывода
# ============================================================

C_RED=$'\033[31m'
C_GREEN=$'\033[32m'
C_YELLOW=$'\033[33m'
C_BLUE=$'\033[34m'
C_RESET=$'\033[0m'

ok() {
    printf '%s[OK]%s %s\n' "$C_GREEN" "$C_RESET" "$*"
}

info() {
    printf '%s[INFO]%s %s\n' "$C_BLUE" "$C_RESET" "$*"
}

warn() {
    printf '%s[WARNING]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"
}

error() {
    printf '%s[ERROR]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2
}

die() {
    error "$*"
    exit 1
}

section() {
    echo ""
    echo "========================================="
    echo "$*"
    echo "========================================="
}


# ============================================================
# 3. Переменные состояния
# ============================================================

SSH_USER="${SSH_USER:-}"
SSH_PORT="${SSH_PORT:-}"
PUBLIC_KEY="${PUBLIC_KEY:-}"

USER_CREATED=0

SSH_CONFIG_EXISTED=0
SOCKET_DROPIN_EXISTED=0

CONFIG_WRITTEN=0
SOCKET_WRITTEN=0
PORT_RESERVED=0

AUTHORIZED_KEYS_EXISTED=0
KEY_ADDED=0

UFW_ACTIVE=0
UFW_22_EXISTED=0
UFW_NEW_PORT_ADDED=0

BACKUP_CREATED=0
ROLLBACK_RUNNING=0

OLD_SSH_CONFIG_BACKUP=""
OLD_SOCKET_BACKUP=""
OLD_AUTHORIZED_KEYS_BACKUP=""

CURRENT_USER=""


# ============================================================
# 4. Проверка sudo
# ============================================================

require_sudo() {

    if [[ "$EUID" -eq 0 ]]; then
        return 0
    fi

    if ! sudo -v >/dev/null 2>&1; then
        die "Необходимы права sudo."
    fi
}


# ============================================================
# 5. Проверка команды
# ============================================================

require_command() {

    local command_name="$1"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        die "Не найдена команда: $command_name"
    fi
}


# ============================================================
# 6. Вспомогательные функции
# ============================================================

# Безопасное чтение значения из metadata backup.
# Файл НЕ исполняется (в отличие от source).
meta_get() {

    local key="$1"
    local default="${2:-}"
    local value=""

    if [[ -f "$CURRENT_BACKUP/metadata" ]]; then
        value="$(
            sudo sed -n "s/^${key}='\(.*\)'$/\1/p" \
                "$CURRENT_BACKUP/metadata" 2>/dev/null |
                head -n 1
        )"
    fi

    printf '%s' "${value:-$default}"
}


# Резервирование порта, если он попадает
# в диапазон эфемерных портов (по умолчанию 32768-60999).
#
# Без резервирования исходящее соединение может
# временно занять SSH-порт, и sshd не сможет
# запуститься после рестарта.
reserve_port_if_needed() {

    local port="$1"
    local lo hi current merged

    if [[ ! -r /proc/sys/net/ipv4/ip_local_port_range ]]; then
        return 0
    fi

    read -r lo hi < /proc/sys/net/ipv4/ip_local_port_range

    if (( port < lo || port > hi )); then
        info "Порт $port вне эфемерного диапазона ($lo-$hi)."
        return 0
    fi

    warn "Порт $port попадает в эфемерный диапазон ($lo-$hi)."

    current="$(sysctl -n net.ipv4.ip_local_reserved_ports 2>/dev/null || true)"

    if [[ ",$current," == *",$port,"* ]]; then
        info "Порт уже зарезервирован в ip_local_reserved_ports."
        PORT_RESERVED=1
        return 0
    fi

    if [[ -n "$current" ]]; then
        merged="$current,$port"
    else
        merged="$port"
    fi

    sudo tee "$SYSCTL_RESERVE_FILE" >/dev/null <<EOF
# Зарезервировано setup-ssh-settings.sh
net.ipv4.ip_local_reserved_ports = $merged
EOF

    sudo sysctl -p "$SYSCTL_RESERVE_FILE" >/dev/null

    PORT_RESERVED=1

    ok "Порт $port зарезервирован (net.ipv4.ip_local_reserved_ports)."
}


# ============================================================
# 7. Rollback
# ============================================================

rollback() {

    local exit_code=$?

    # Если всё завершилось успешно — rollback не нужен.
    if [[ "$exit_code" -eq 0 ]]; then
        return 0
    fi

    # Защита от повторного запуска rollback.
    if [[ "$ROLLBACK_RUNNING" -eq 1 ]]; then
        return 0
    fi

    ROLLBACK_RUNNING=1

    # Если изменения ещё не вносились — откатывать нечего.
    if [[ "$BACKUP_CREATED" -eq 0 &&
          "$USER_CREATED" -eq 0 &&
          "$KEY_ADDED" -eq 0 &&
          "$CONFIG_WRITTEN" -eq 0 &&
          "$SOCKET_WRITTEN" -eq 0 ]]; then

        echo ""
        info "Изменения не вносились — откат не требуется."
        exit "$exit_code"
    fi

    echo ""
    echo "========================================="
    echo "ROLLBACK"
    echo "========================================="
    echo ""

    error "Скрипт завершился с ошибкой."
    info "Попытка откатить изменения..."

    # --------------------------------------------------------
    # SSH CONFIG
    # --------------------------------------------------------

    if [[ "$CONFIG_WRITTEN" -eq 1 ]]; then

        if [[ "$SSH_CONFIG_EXISTED" -eq 1 ]]; then

            if [[ -f "$OLD_SSH_CONFIG_BACKUP" ]]; then

                sudo cp -a \
                    "$OLD_SSH_CONFIG_BACKUP" \
                    "$SSH_CONFIG"

                ok "Восстановлен старый SSH-конфиг."

            fi

        else

            sudo rm -f "$SSH_CONFIG"

            ok "Удалён созданный SSH-конфиг."

        fi

    fi


    # --------------------------------------------------------
    # SSH SOCKET
    # --------------------------------------------------------

    if [[ "$SOCKET_WRITTEN" -eq 1 ]]; then

        if [[ "$SOCKET_DROPIN_EXISTED" -eq 1 ]]; then

            if [[ -f "$OLD_SOCKET_BACKUP" ]]; then

                sudo mkdir -p "$SOCKET_DROPIN_DIR"

                sudo cp -a \
                    "$OLD_SOCKET_BACKUP" \
                    "$SOCKET_DROPIN"

                ok "Восстановлен старый ssh.socket override."

            fi

        else

            sudo rm -f "$SOCKET_DROPIN"

            ok "Удалён созданный ssh.socket override."

        fi

    fi


    # --------------------------------------------------------
    # authorized_keys
    # --------------------------------------------------------

    if [[ "$KEY_ADDED" -eq 1 ]]; then

        if [[ "$AUTHORIZED_KEYS_EXISTED" -eq 1 ]]; then

            if [[ -f "$OLD_AUTHORIZED_KEYS_BACKUP" ]]; then

                sudo cp -a \
                    "$OLD_AUTHORIZED_KEYS_BACKUP" \
                    "$AUTHORIZED_KEYS"

                ok "Восстановлен старый authorized_keys."

            fi

        else

            sudo rm -f "$AUTHORIZED_KEYS"

            ok "Удалён созданный authorized_keys."

        fi

    fi


    # --------------------------------------------------------
    # UFW
    # --------------------------------------------------------

    if [[ "$UFW_ACTIVE" -eq 1 ]]; then

        # Удаляем только правило нового порта,
        # если его добавил наш скрипт.
        if [[ "$UFW_NEW_PORT_ADDED" -eq 1 ]]; then

            sudo ufw --force delete allow "$SSH_PORT/tcp" \
                >/dev/null 2>&1 || true

            ok "Удалено правило UFW $SSH_PORT/tcp."

        fi


        # Восстанавливаем 22 только если оно существовало
        # до запуска скрипта.
        if [[ "$UFW_22_EXISTED" -eq 1 ]]; then

            if ! sudo ufw status |
                grep -qE '^22/tcp[[:space:]]+ALLOW[[:space:]]+Anywhere'; then

                sudo ufw allow 22/tcp \
                    >/dev/null 2>&1 || true

                ok "Восстановлено правило UFW 22/tcp."

            fi

        fi

    fi


    # --------------------------------------------------------
    # Пользователь
    # --------------------------------------------------------

    # ВАЖНО:
    #
    # Если пользователь был создан этим скриптом,
    # удаляем его только при rollback.
    #
    # Существующего пользователя никогда не удаляем.
    #

    if [[ "$USER_CREATED" -eq 1 ]]; then

        if id "$SSH_USER" >/dev/null 2>&1; then

            sudo userdel -r "$SSH_USER" \
                >/dev/null 2>&1 || true

            ok "Удалён пользователь, созданный скриптом: $SSH_USER"

        fi

    fi


    # --------------------------------------------------------
    # systemd
    # --------------------------------------------------------

    # Перезапускаем только если конфигурация менялась
    # и только тот механизм, который реально активен.

    if [[ "$CONFIG_WRITTEN" -eq 1 || "$SOCKET_WRITTEN" -eq 1 ]]; then

        sudo systemctl daemon-reload >/dev/null 2>&1 || true

        if systemctl is-active --quiet ssh.socket; then

            sudo systemctl restart ssh.socket \
                >/dev/null 2>&1 || true

        else

            sudo systemctl restart "$SSH_SERVICE" \
                >/dev/null 2>&1 || true

        fi

    fi


    echo ""
    info "Rollback завершён."
    echo ""
    echo "Backup:"
    echo "$CURRENT_BACKUP"
    echo ""

    exit "$exit_code"
}


# ============================================================
# 8. Ручной rollback
# ============================================================

manual_rollback() {

    section "ROLLBACK"

    if [[ "$EUID" -ne 0 ]]; then

        die "Запустите rollback через sudo: sudo $SCRIPT_NAME --rollback"

    fi

    if [[ ! -d "$CURRENT_BACKUP" ]]; then

        die "Backup не найден: $CURRENT_BACKUP"

    fi

    info "Найден backup:"
    echo "$CURRENT_BACKUP"
    echo ""

    read -rp "Выполнить rollback? [y/N]: " CONFIRM

    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Отменено."
        exit 0
    fi


    # --------------------------------------------------------
    # Читаем metadata backup (без source)
    # --------------------------------------------------------

    RB_SSH_CONFIG_EXISTED="$(meta_get BACKUP_SSH_CONFIG_EXISTED 0)"
    RB_SOCKET_EXISTED="$(meta_get BACKUP_SOCKET_EXISTED 0)"
    RB_UFW_ACTIVE="$(meta_get BACKUP_UFW_ACTIVE 0)"
    RB_UFW_22_EXISTED="$(meta_get BACKUP_UFW_22_EXISTED 0)"
    RB_UFW_NEW_PORT_ADDED="$(meta_get BACKUP_UFW_NEW_PORT_ADDED 0)"
    RB_AK_EXISTED="$(meta_get BACKUP_AUTHORIZED_KEYS_EXISTED 0)"
    RB_AK_PATH="$(meta_get BACKUP_AUTHORIZED_KEYS_PATH "")"
    RB_USER_CREATED="$(meta_get BACKUP_USER_CREATED 0)"
    RB_SSH_USER="$(meta_get BACKUP_SSH_USER "")"
    RB_SSH_PORT="$(meta_get BACKUP_SSH_PORT "")"


    # --------------------------------------------------------
    # Восстанавливаем SSH config
    # --------------------------------------------------------

    if [[ "$RB_SSH_CONFIG_EXISTED" -eq 1 ]]; then

        if [[ -f "$CURRENT_BACKUP/sshd_config" ]]; then

            sudo cp -a \
                "$CURRENT_BACKUP/sshd_config" \
                "$SSH_CONFIG"

            ok "SSH-конфиг восстановлен."

        fi

    else

        sudo rm -f "$SSH_CONFIG"

        ok "SSH-конфиг удалён."

    fi


    # --------------------------------------------------------
    # ssh.socket
    # --------------------------------------------------------

    if [[ "$RB_SOCKET_EXISTED" -eq 1 ]]; then

        if [[ -f "$CURRENT_BACKUP/socket-override" ]]; then

            sudo mkdir -p "$SOCKET_DROPIN_DIR"

            sudo cp -a \
                "$CURRENT_BACKUP/socket-override" \
                "$SOCKET_DROPIN"

            ok "ssh.socket override восстановлен."

        fi

    else

        sudo rm -f "$SOCKET_DROPIN"

        ok "ssh.socket override удалён."

    fi


    # --------------------------------------------------------
    # UFW
    # --------------------------------------------------------

    if [[ "$RB_UFW_ACTIVE" -eq 1 ]]; then

        if [[ "$RB_UFW_NEW_PORT_ADDED" -eq 1 ]]; then

            if [[ -n "$RB_SSH_PORT" ]]; then

                sudo ufw --force delete allow "$RB_SSH_PORT/tcp" \
                    >/dev/null 2>&1 || true

                ok "Правило $RB_SSH_PORT/tcp удалено."

            else

                warn "Порт из backup не определён — правило UFW не удалено."

            fi

        fi


        if [[ "$RB_UFW_22_EXISTED" -eq 1 ]]; then

            if ! sudo ufw status |
                grep -qE '^22/tcp[[:space:]]+ALLOW[[:space:]]+Anywhere'; then

                sudo ufw allow 22/tcp \
                    >/dev/null 2>&1 || true

                ok "Правило 22/tcp восстановлено."

            fi

        fi

    fi


    # --------------------------------------------------------
    # authorized_keys
    # --------------------------------------------------------

    if [[ "$RB_AK_EXISTED" -eq 1 ]]; then

        if [[ -f "$CURRENT_BACKUP/authorized_keys" && -n "$RB_AK_PATH" ]]; then

            sudo mkdir -p "$(dirname "$RB_AK_PATH")"

            sudo cp -a \
                "$CURRENT_BACKUP/authorized_keys" \
                "$RB_AK_PATH"

            ok "authorized_keys восстановлен."

        fi

    elif [[ -n "$RB_AK_PATH" ]]; then

        # Файл был создан скриптом — удаляем его.
        sudo rm -f "$RB_AK_PATH"

        ok "Созданный скриптом authorized_keys удалён."

    fi


    # --------------------------------------------------------
    # Пользователь, созданный скриптом
    # --------------------------------------------------------

    if [[ "$RB_USER_CREATED" -eq 1 && -n "$RB_SSH_USER" ]]; then

        if id "$RB_SSH_USER" >/dev/null 2>&1; then

            echo ""
            read -rp \
                "Удалить пользователя $RB_SSH_USER, созданного скриптом (вместе с home)? [y/N]: " \
                CONFIRM_USER

            if [[ "$CONFIRM_USER" =~ ^[Yy]$ ]]; then

                sudo userdel -r "$RB_SSH_USER" \
                    >/dev/null 2>&1 || true

                ok "Пользователь $RB_SSH_USER удалён."

            else

                info "Пользователь $RB_SSH_USER оставлен."

            fi

        fi

    fi


    # --------------------------------------------------------
    # systemd
    # --------------------------------------------------------

    sudo systemctl daemon-reload


    if systemctl is-active --quiet ssh.socket; then

        sudo systemctl restart ssh.socket \
            >/dev/null 2>&1 || true

    else

        sudo systemctl restart "$SSH_SERVICE" \
            >/dev/null 2>&1 || true

    fi


    echo ""
    ok "Rollback завершён."
    echo ""
    echo "Проверьте SSH:"
    echo "sudo sshd -T | grep -E '^(port|permitrootlogin|passwordauthentication|allowusers) '"
    echo ""

    exit 0
}


# ============================================================
# 9. --rollback
# ============================================================

if [[ "${1:-}" == "--rollback" ]]; then

    require_sudo
    manual_rollback

fi


# ============================================================
# 10. Trap
# ============================================================

trap rollback EXIT


# ============================================================
# 11. Проверка sudo
# ============================================================

require_sudo


# ============================================================
# 12. Проверяем необходимые команды
# ============================================================

section "Проверка системы"

require_command sshd
require_command ssh-keygen
require_command ss
require_command systemctl
require_command awk
require_command grep
require_command sed
require_command shuf
require_command getent

ok "Необходимые команды найдены."


# ============================================================
# 13. Текущий пользователь
# ============================================================

CURRENT_USER="${SUDO_USER:-$(id -un)}"

info "Текущий пользователь: $CURRENT_USER"


# ============================================================
# 14. Ввод параметров
# ============================================================

section "Параметры"


# ------------------------------------------------------------
# SSH USER
# ------------------------------------------------------------

if [[ -z "$SSH_USER" ]]; then

    read -rp "Имя главного SSH-пользователя: " SSH_USER

fi

if [[ -z "$SSH_USER" ]]; then
    die "Имя пользователя не может быть пустым."
fi

if ! [[ "$SSH_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    die "Некорректное имя пользователя."
fi


# ------------------------------------------------------------
# Проверка текущего пользователя
# ------------------------------------------------------------

if [[ "$CURRENT_USER" != "$SSH_USER" ]]; then

    warn "Текущий пользователь: $CURRENT_USER"
    warn "После применения AllowUsers будет разрешён только: $SSH_USER"
    warn "Пользователь $CURRENT_USER больше не сможет входить через SSH."

    read -rp "Продолжить? [y/N]: " CONFIRM

    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        die "Отменено."
    fi

fi


# ------------------------------------------------------------
# SSH PORT
# ------------------------------------------------------------

if [[ -z "$SSH_PORT" ]]; then

    read -rp \
        "SSH-порт [Enter = случайный 20000-32767]: " \
        SSH_PORT

fi

if [[ -z "$SSH_PORT" ]]; then

    # Вне стандартного диапазона эфемерных портов (32768-60999).
    SSH_PORT="$(shuf -i 20000-32767 -n 1)"

    info "Случайно выбран порт: $SSH_PORT"

fi

if ! [[ "$SSH_PORT" =~ ^[1-9][0-9]*$ ]]; then
    die "SSH-порт должен быть числом без ведущих нулей."
fi

if (( SSH_PORT < 20000 || SSH_PORT > 60000 )); then
    die "SSH-порт должен быть от 20000 до 60000."
fi


# ------------------------------------------------------------
# PUBLIC KEY
# ------------------------------------------------------------

if [[ -z "$PUBLIC_KEY" ]]; then

    read -rp \
        "Ваш публичный SSH-ключ: " \
        PUBLIC_KEY

fi

if [[ -z "$PUBLIC_KEY" ]]; then
    die "Публичный SSH-ключ не может быть пустым."
fi


# ============================================================
# 15. Проверка SSH-ключа
# ============================================================

section "Проверка SSH-ключа"

# Защита от вставки приватного ключа:
# ssh-keygen -lf принимает и приватные ключи тоже.
KEY_TYPE="${PUBLIC_KEY%% *}"

case "$KEY_TYPE" in
    ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) ;;
    *)
        die "Ключ не похож на публичный (тип: '$KEY_TYPE'). Ожидается ssh-ed25519, ssh-rsa, ecdsa-sha2-* или sk-*. Приватный ключ вводить нельзя."
        ;;
esac


KEY_FINGERPRINT="$(
    printf '%s\n' "$PUBLIC_KEY" |
        ssh-keygen -lf - 2>/dev/null || true
)"

if [[ -z "$KEY_FINGERPRINT" ]]; then

    die "Указанный ключ не является корректным публичным SSH-ключом."

fi

ok "SSH-ключ распознан:"
echo "$KEY_FINGERPRINT"


# ============================================================
# 16. Показываем настройки
# ============================================================

section "Выбранные настройки"

echo "SSH USER : $SSH_USER"
echo "SSH PORT : $SSH_PORT"
echo "SSH KEY  : $KEY_FINGERPRINT"
echo ""
echo "SSH config:"
echo "$SSH_CONFIG"
echo ""
echo "ssh.socket override:"
echo "$SOCKET_DROPIN"
echo ""

read -rp "Применить настройки? [y/N]: " CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    die "Отменено."
fi


# ============================================================
# 17. Проверка свободного порта
# ============================================================

section "Проверка порта $SSH_PORT"

BUSY_PORT="$(
    sudo ss -lHnt 2>/dev/null |
        awk -v port="$SSH_PORT" '
            {
                address=$4

                if (address ~ /^\[/) {
                    gsub(/^\[/, "", address)
                    split(address, parts, /\]:/)
                    current_port=parts[2]
                } else {
                    n=split(address, parts, ":")
                    current_port=parts[n]
                }

                if (current_port == port) {
                    print
                }
            }
        ' || true
)"

if [[ -n "$BUSY_PORT" ]]; then

    echo "$BUSY_PORT"

    die "Порт $SSH_PORT уже используется."

fi

ok "Порт $SSH_PORT свободен."


# ============================================================
# 18. Создание backup
# ============================================================

section "Создание backup"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

NEW_BACKUP="$BACKUP_ROOT/$TIMESTAMP"

sudo mkdir -p "$NEW_BACKUP"

sudo chmod 700 "$BACKUP_ROOT" "$NEW_BACKUP"

# Удаляем старую ссылку current
sudo rm -f "$CURRENT_BACKUP"

sudo ln -s "$NEW_BACKUP" "$CURRENT_BACKUP"

BACKUP_CREATED=1


# ------------------------------------------------------------
# Ротация backup: храним KEEP_BACKUPS последних
# ------------------------------------------------------------

sudo find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d |
    sort |
    head -n "-$KEEP_BACKUPS" |
    while IFS= read -r OLD_BACKUP_DIR; do
        sudo rm -rf "$OLD_BACKUP_DIR"
    done


# ------------------------------------------------------------
# Backup metadata
# ------------------------------------------------------------

{
    echo "BACKUP_CREATED_AT='$TIMESTAMP'"
    echo "BACKUP_SSH_PORT='$SSH_PORT'"
    echo "BACKUP_SSH_USER='$SSH_USER'"
    echo "BACKUP_SSH_CONFIG_EXISTED='$([[ -f "$SSH_CONFIG" ]] && echo 1 || echo 0)'"
    echo "BACKUP_SOCKET_EXISTED='$([[ -f "$SOCKET_DROPIN" ]] && echo 1 || echo 0)'"
} | sudo tee "$NEW_BACKUP/metadata" >/dev/null


# ------------------------------------------------------------
# Backup SSH config
# ------------------------------------------------------------

if [[ -f "$SSH_CONFIG" ]]; then

    SSH_CONFIG_EXISTED=1

    sudo cp -a \
        "$SSH_CONFIG" \
        "$NEW_BACKUP/sshd_config"

    OLD_SSH_CONFIG_BACKUP="$NEW_BACKUP/sshd_config"

fi


# ------------------------------------------------------------
# Backup socket override
# ------------------------------------------------------------

if [[ -f "$SOCKET_DROPIN" ]]; then

    SOCKET_DROPIN_EXISTED=1

    sudo cp -a \
        "$SOCKET_DROPIN" \
        "$NEW_BACKUP/socket-override"

    OLD_SOCKET_BACKUP="$NEW_BACKUP/socket-override"

fi


ok "Backup создан:"
echo "$NEW_BACKUP"


# ------------------------------------------------------------
# Резервирование порта (при необходимости)
# ------------------------------------------------------------

reserve_port_if_needed "$SSH_PORT"


# ============================================================
# 19. Пользователь
# ============================================================

section "Пользователь $SSH_USER"

if id "$SSH_USER" >/dev/null 2>&1; then

    info "Пользователь уже существует."

else

    sudo adduser \
        --disabled-password \
        --gecos "" \
        "$SSH_USER"

    USER_CREATED=1

    ok "Пользователь создан."

fi


# ------------------------------------------------------------
# Добавляем sudo
# ------------------------------------------------------------

if getent group sudo >/dev/null 2>&1; then

    sudo usermod -aG sudo "$SSH_USER"

    ok "$SSH_USER добавлен в группу sudo."

else

    warn "Группа sudo не найдена."

fi


# ------------------------------------------------------------
# Определяем HOME
# ------------------------------------------------------------

USER_HOME="$(getent passwd "$SSH_USER" | cut -d: -f6)"

if [[ -z "$USER_HOME" || ! -d "$USER_HOME" ]]; then
    die "Не удалось определить домашний каталог пользователя."
fi


# ============================================================
# 20. authorized_keys
# ============================================================

section "SSH-ключ"

AUTHORIZED_KEYS="$USER_HOME/.ssh/authorized_keys"

USER_GROUP="$(id -gn "$SSH_USER")"

sudo install \
    -d \
    -m 700 \
    -o "$SSH_USER" \
    -g "$USER_GROUP" \
    "$USER_HOME/.ssh"


# ------------------------------------------------------------
# Сохраняем существующий authorized_keys
# ------------------------------------------------------------

if [[ -f "$AUTHORIZED_KEYS" ]]; then

    AUTHORIZED_KEYS_EXISTED=1

    OLD_AUTHORIZED_KEYS_BACKUP="$NEW_BACKUP/authorized_keys"

    sudo cp -a \
        "$AUTHORIZED_KEYS" \
        "$OLD_AUTHORIZED_KEYS_BACKUP"

fi


# ------------------------------------------------------------
# Проверяем, есть ли уже такой ключ
# ------------------------------------------------------------

if sudo grep -Fqx "$PUBLIC_KEY" "$AUTHORIZED_KEYS" 2>/dev/null; then

    info "Этот SSH-ключ уже существует."

else

    printf '%s\n' "$PUBLIC_KEY" |
        sudo tee -a "$AUTHORIZED_KEYS" >/dev/null

    KEY_ADDED=1

    ok "SSH-ключ добавлен."

fi


# ------------------------------------------------------------
# Если файл существовал — сохраняем его состояние
# ------------------------------------------------------------

if [[ "$AUTHORIZED_KEYS_EXISTED" -eq 0 ]]; then

    # Если файл был создан нами, записываем его backup path.
    sudo cp -a \
        "$AUTHORIZED_KEYS" \
        "$NEW_BACKUP/authorized_keys"

fi


sudo chown -R \
    "$SSH_USER:$SSH_USER" \
    "$USER_HOME/.ssh"

sudo chmod 700 \
    "$USER_HOME/.ssh"

sudo chmod 600 \
    "$AUTHORIZED_KEYS"


# Сохраняем состояние для ручного rollback
sudo tee -a "$NEW_BACKUP/metadata" >/dev/null <<EOF
BACKUP_USER_CREATED='$USER_CREATED'
BACKUP_AUTHORIZED_KEYS_EXISTED='$AUTHORIZED_KEYS_EXISTED'
BACKUP_AUTHORIZED_KEYS_PATH='$AUTHORIZED_KEYS'
EOF


ok "authorized_keys настроен."


# ============================================================
# 21. SSH config
# ============================================================

section "SSH-конфигурация"

sudo install \
    -d \
    -m 755 \
    /etc/ssh/sshd_config.d


sudo tee "$SSH_CONFIG" >/dev/null <<EOF
# ============================================================
# SSH settings managed by setup-ssh-settings.sh
# ============================================================

Port $SSH_PORT

PermitRootLogin no

PasswordAuthentication no

KbdInteractiveAuthentication no

PubkeyAuthentication yes

AllowUsers $SSH_USER

MaxAuthTries 4

LoginGraceTime 30

ClientAliveInterval 300

ClientAliveCountMax 2

X11Forwarding no

AllowAgentForwarding no

AllowTcpForwarding no
EOF

CONFIG_WRITTEN=1


ok "Создан:"
echo "$SSH_CONFIG"


# ============================================================
# 22. Проверка sshd -t
# ============================================================

section "Проверка синтаксиса SSH"

if ! sudo sshd -t; then

    die "sshd -t обнаружил ошибку."

fi

ok "SSH-конфигурация синтаксически корректна."


# ============================================================
# 23. Эффективный SSH config
# ============================================================

section "Эффективные настройки SSH"

EFFECTIVE_CONFIG="$(sudo sshd -T)"


first_value() {

    local key="$1"

    awk -v key="$key" '
        $1 == key {
            print $2
            exit
        }
    ' <<< "$EFFECTIVE_CONFIG"
}


# Возвращает остаток строки после ключа.
# Нужно для allowusers — там может быть список имён.
full_value() {

    local key="$1"

    awk -v key="$key" '
        $1 == key {
            $1 = ""
            sub(/^ /, "")
            print
            exit
        }
    ' <<< "$EFFECTIVE_CONFIG"
}


# Показывает, откуда sshd берёт Port,
# если эффективный порт не совпал с ожидаемым.
show_port_sources() {

    echo ""
    warn "Ищу все директивы Port в конфигурации sshd:"

    sudo grep -HniE '^[[:space:]]*Port[[:space:]]+[0-9]+' \
        /etc/ssh/sshd_config \
        /etc/ssh/sshd_config.d/*.conf \
        2>/dev/null | sed 's/^/  /' || true

    echo ""
    warn "Строка Include в /etc/ssh/sshd_config:"

    sudo grep -HniE '^[[:space:]]*Include' \
        /etc/ssh/sshd_config 2>/dev/null | sed 's/^/  /' || true

    echo ""
    info "sshd использует ПЕРВОЕ полученное значение Port."
    info "Строки /etc/ssh/sshd_config ДО строки Include важнее всех drop-in."
    info "Drop-in файлы читаются в лексикографическом порядке"
    info "(01-my-settings-ssh.conf раньше, чем 50-cloud-init.conf)."
    info "Удалите конфликтующую директиву Port и запустите скрипт снова."
}


count_value() {

    local key="$1"

    awk -v key="$key" '
        $1 == key {
            count++
        }

        END {
            print count + 0
        }
    ' <<< "$EFFECTIVE_CONFIG"
}


EFFECTIVE_PORT="$(first_value port)"
EFFECTIVE_ROOT="$(first_value permitrootlogin)"
EFFECTIVE_PASSWORD="$(first_value passwordauthentication)"
EFFECTIVE_INTERACTIVE="$(first_value kbdinteractiveauthentication)"
EFFECTIVE_PUBKEY="$(first_value pubkeyauthentication)"
EFFECTIVE_USER="$(full_value allowusers)"


echo "port                       : $EFFECTIVE_PORT"
echo "permitrootlogin            : $EFFECTIVE_ROOT"
echo "passwordauthentication     : $EFFECTIVE_PASSWORD"
echo "kbdinteractiveauthentication: $EFFECTIVE_INTERACTIVE"
echo "pubkeyauthentication       : $EFFECTIVE_PUBKEY"
echo "allowusers                 : $EFFECTIVE_USER"


# ------------------------------------------------------------
# Проверки
# ------------------------------------------------------------

if [[ "$EFFECTIVE_PORT" != "$SSH_PORT" ]]; then
    show_port_sources
    die "sshd использует порт $EFFECTIVE_PORT вместо $SSH_PORT."
fi

if [[ "$EFFECTIVE_ROOT" != "no" ]]; then
    die "PermitRootLogin не отключён."
fi

if [[ "$EFFECTIVE_PASSWORD" != "no" ]]; then
    die "PasswordAuthentication не отключён."
fi

if [[ "$EFFECTIVE_INTERACTIVE" != "no" ]]; then
    die "KbdInteractiveAuthentication не отключён."
fi

if [[ "$EFFECTIVE_PUBKEY" != "yes" ]]; then
    die "PubkeyAuthentication не включён."
fi

if [[ "$EFFECTIVE_USER" != "$SSH_USER" ]]; then
    die "AllowUsers настроен неправильно (эффективное значение: '$EFFECTIVE_USER', ожидалось: '$SSH_USER')."
fi


ok "Эффективные параметры SSH соответствуют настройкам."


# ------------------------------------------------------------
# Проверяем несколько Port
# ------------------------------------------------------------

PORT_COUNT="$(count_value port)"

if (( PORT_COUNT > 1 )); then

    warn "Обнаружено несколько директив Port."

    awk '$1=="port"{print "  "$0}' <<< "$EFFECTIVE_CONFIG"

    warn "SSH может слушать несколько портов."

fi


# ============================================================
# 24. systemd ssh.socket
# ============================================================

section "systemd ssh.socket"

HAS_SOCKET=0

if systemctl cat ssh.socket >/dev/null 2>&1; then

    HAS_SOCKET=1

    info "ssh.socket найден."

    sudo mkdir -p "$SOCKET_DROPIN_DIR"


    sudo tee "$SOCKET_DROPIN" >/dev/null <<EOF
[Socket]
ListenStream=
ListenStream=$SSH_PORT
EOF

    SOCKET_WRITTEN=1


    ok "Создан:"
    echo "$SOCKET_DROPIN"

else

    info "ssh.socket не используется."

fi


# ============================================================
# 25. systemd reload
# ============================================================

section "systemd daemon-reload"

sudo systemctl daemon-reload

ok "systemd перечитал конфигурацию."


# ------------------------------------------------------------
# Проверяем Listen
# ------------------------------------------------------------

if (( HAS_SOCKET )); then

    echo ""
    echo "--- ssh.socket Listen ---"

    sudo systemctl show \
        ssh.socket \
        -p Listen

fi


# ============================================================
# 26. UFW
# ============================================================

section "UFW"

if command -v ufw >/dev/null 2>&1 &&
    sudo ufw status 2>/dev/null |
        grep -q "Status: active"; then

    UFW_ACTIVE=1

    info "UFW активен."


    # --------------------------------------------------------
    # Проверяем старое правило 22
    # --------------------------------------------------------

    if sudo ufw status |
        grep -qE '^22/tcp[[:space:]]+ALLOW[[:space:]]+Anywhere'; then

        UFW_22_EXISTED=1

        info "До изменений UFW разрешал 22/tcp (Anywhere)."

    else

        UFW_22_EXISTED=0

        info "До изменений правило 22/tcp отсутствовало."

    fi


    # --------------------------------------------------------
    # Новый SSH-порт
    # --------------------------------------------------------

    if sudo ufw status |
        grep -qE "^${SSH_PORT}/tcp[[:space:]]+ALLOW[[:space:]]+Anywhere"; then

        ok "Порт $SSH_PORT/tcp уже разрешён (Anywhere)."

    else

        sudo ufw allow "$SSH_PORT/tcp"

        UFW_NEW_PORT_ADDED=1

        ok "Разрешён $SSH_PORT/tcp."

    fi


    # --------------------------------------------------------
    # Удаляем 22
    # --------------------------------------------------------

    if [[ "$UFW_22_EXISTED" -eq 1 ]]; then

        sudo ufw --force delete allow 22/tcp

        ok "Правило 22/tcp (Anywhere) удалено."

    else

        ok "Правила 22/tcp (Anywhere) нет."

    fi


    # --------------------------------------------------------
    # Проверяем новый порт
    # --------------------------------------------------------

    if sudo ufw status |
        grep -qE "^${SSH_PORT}/tcp[[:space:]]+ALLOW[[:space:]]+Anywhere"; then

        ok "UFW разрешает $SSH_PORT/tcp (Anywhere)."

    else

        die "UFW не разрешает новый SSH-порт."

    fi


    # --------------------------------------------------------
    # Проверяем 22
    # --------------------------------------------------------

    if sudo ufw status |
        grep -qE '^22/tcp[[:space:]]+ALLOW[[:space:]]+Anywhere'; then

        die "UFW всё ещё разрешает 22/tcp (Anywhere)."

    fi

    ok "UFW больше не разрешает 22/tcp (Anywhere)."

    # Source-specific правила скрипт не трогает,
    # но предупреждает о них.
    if sudo ufw status |
        grep -qE '^22/tcp[[:space:]]+ALLOW'; then

        warn "Остались правила 22/tcp с ограничением по источнику:"

        sudo ufw status |
            grep -E '^22/tcp[[:space:]]+ALLOW' |
            sed 's/^/  /'

        warn "Удалите их вручную, если они не нужны."

    fi

else

    info "UFW не установлен или не активен."
    info "Настройка UFW пропущена."

fi


# Сохраняем UFW state в metadata
sudo tee -a "$NEW_BACKUP/metadata" >/dev/null <<EOF
BACKUP_UFW_ACTIVE='$UFW_ACTIVE'
BACKUP_UFW_22_EXISTED='$UFW_22_EXISTED'
BACKUP_UFW_NEW_PORT_ADDED='$UFW_NEW_PORT_ADDED'
BACKUP_PORT_RESERVED='$PORT_RESERVED'
EOF


# ============================================================
# 27. Перезапуск SSH
# ============================================================

section "Перезапуск SSH"

if (( HAS_SOCKET )); then

    # При socket activation сначала останавливаем ssh.service,
    # затем перезапускаем socket.
    sudo systemctl stop "$SSH_SERVICE" \
        >/dev/null 2>&1 || true

    sudo systemctl reset-failed \
        ssh.socket \
        "$SSH_SERVICE" \
        >/dev/null 2>&1 || true


    if ! sudo systemctl restart ssh.socket; then

        warn "ssh.socket не запустился с указанной конфигурацией."

        echo ""
        echo "--- ssh.socket status ---"

        sudo systemctl status \
            ssh.socket \
            --no-pager \
            || true

        echo ""
        echo "--- journal ---"

        sudo journalctl \
            -u ssh.socket \
            -n 20 \
            --no-pager \
            || true

        die "Не удалось запустить ssh.socket."

    fi

    ok "ssh.socket перезапущен."

else

    if ! sudo systemctl restart "$SSH_SERVICE"; then

        die "Не удалось перезапустить $SSH_SERVICE."

    fi

    ok "$SSH_SERVICE перезапущен."

fi


sleep 2


# ============================================================
# 28. Реальные listening ports
# ============================================================

section "Проверка listening ports"

echo "--- SSH-порты ---"

sudo ss -lntp |
    grep -E ':(22|'"$SSH_PORT"')\b' \
    || true


# ============================================================
# 29. Проверяем новый порт
# ============================================================

if ! sudo ss -lHnt |
    awk -v port="$SSH_PORT" '
        {
            address=$4

            if (address ~ /^\[/) {
                gsub(/^\[/, "", address)
                split(address, parts, /\]:/)
                current_port=parts[2]
            } else {
                n=split(address, parts, ":")
                current_port=parts[n]
            }

            if (current_port == port) {
                found=1
            }
        }

        END {
            exit !found
        }
    '; then

    echo ""
    echo "--- ssh.service ---"

    sudo systemctl status \
        "$SSH_SERVICE" \
        --no-pager \
        || true

    echo ""
    echo "--- ssh.socket ---"

    sudo systemctl status \
        ssh.socket \
        --no-pager \
        || true

    echo ""
    echo "--- ssh.socket Listen ---"

    sudo systemctl show \
        ssh.socket \
        -p Listen \
        || true

    die "Порт $SSH_PORT не слушается."

fi

ok "Порт $SSH_PORT реально слушается."


# ============================================================
# 30. Проверяем порт 22
# ============================================================

section "Проверка старого порта 22"

if sudo ss -lHnt |
    awk '
        {
            address=$4

            if (address ~ /^\[/) {
                gsub(/^\[/, "", address)
                split(address, parts, /\]:/)
                current_port=parts[2]
            } else {
                n=split(address, parts, ":")
                current_port=parts[n]
            }

            if (current_port == "22") {
                found=1
            }
        }

        END {
            exit !found
        }
    '; then

    warn "Порт 22 всё ещё слушается каким-то процессом."

    sudo ss -lntp |
        awk '
            {
                address=$4

                if (address ~ /:22$/) {
                    print
                }
            }
        '

else

    ok "Порт 22 не слушается."

fi


# ============================================================
# 31. Локальная проверка SSH banner
# ============================================================

section "Проверка SSH-сервиса"

BANNER="$(
    timeout 5 \
        bash -c \
        "exec 3<>/dev/tcp/127.0.0.1/$SSH_PORT; head -c 40 <&3" \
        2>/dev/null \
        || true
)"

if [[ "$BANNER" == SSH-* ]]; then

    BANNER_CLEAN="${BANNER%%$'\r'*}"

    ok "SSH banner получен:"
    echo "$BANNER_CLEAN"

else

    warn "SSH banner не получен."

fi


# ============================================================
# 32. Проверка пользователя
# ============================================================

section "Проверка пользователя"

id "$SSH_USER"

if id -nG "$SSH_USER" |
    grep -qw sudo; then

    ok "$SSH_USER имеет sudo."

else

    die "$SSH_USER не имеет sudo."

fi


# ============================================================
# 33. Проверка SSH-файлов
# ============================================================

section "Проверка SSH-файлов"

sudo ls -ld "$USER_HOME/.ssh"
sudo ls -l "$AUTHORIZED_KEYS"


SSH_DIR_PERMISSIONS="$(
    sudo stat -c '%a' "$USER_HOME/.ssh"
)"

AUTHORIZED_KEYS_PERMISSIONS="$(
    sudo stat -c '%a' "$AUTHORIZED_KEYS"
)"


if [[ "$SSH_DIR_PERMISSIONS" == "700" ]]; then

    ok ".ssh = 700"

else

    die "Неправильные права .ssh: $SSH_DIR_PERMISSIONS"

fi


if [[ "$AUTHORIZED_KEYS_PERMISSIONS" == "600" ]]; then

    ok "authorized_keys = 600"

else

    die "Неправильные права authorized_keys: $AUTHORIZED_KEYS_PERMISSIONS"

fi


# ============================================================
# 34. Проверка authorized_keys
# ============================================================

section "Проверка authorized_keys"

if sudo test -s "$AUTHORIZED_KEYS"; then

    ok "authorized_keys существует и не пуст."

else

    die "authorized_keys отсутствует или пуст."

fi


# ============================================================
# 35. Финальный UFW
# ============================================================

section "Финальный UFW"

if (( UFW_ACTIVE )); then

    sudo ufw status numbered

else

    info "UFW не активен."

fi


# ============================================================
# 36. Финальная проверка
# ============================================================

section "Финальная проверка"

FINAL_CONFIG="$(sudo sshd -T)"

FINAL_PORT="$(
    awk '$1=="port"{print $2; exit}' <<< "$FINAL_CONFIG"
)"

FINAL_ROOT="$(
    awk '$1=="permitrootlogin"{print $2; exit}' <<< "$FINAL_CONFIG"
)"

FINAL_PASSWORD="$(
    awk '$1=="passwordauthentication"{print $2; exit}' <<< "$FINAL_CONFIG"
)"

FINAL_INTERACTIVE="$(
    awk '$1=="kbdinteractiveauthentication"{print $2; exit}' <<< "$FINAL_CONFIG"
)"

FINAL_PUBKEY="$(
    awk '$1=="pubkeyauthentication"{print $2; exit}' <<< "$FINAL_CONFIG"
)"

FINAL_USER="$(
    awk '$1=="allowusers"{ $1=""; sub(/^ /,""); print; exit }' <<< "$FINAL_CONFIG"
)"


if [[ "$FINAL_PORT" != "$SSH_PORT" ]]; then
    show_port_sources
    die "Финальная проверка: неправильный SSH-порт (эффективный: $FINAL_PORT)."
fi

if [[ "$FINAL_ROOT" != "no" ]]; then
    die "Финальная проверка: root login не отключён."
fi

if [[ "$FINAL_PASSWORD" != "no" ]]; then
    die "Финальная проверка: password authentication не отключён."
fi

if [[ "$FINAL_INTERACTIVE" != "no" ]]; then
    die "Финальная проверка: keyboard-interactive не отключён."
fi

if [[ "$FINAL_PUBKEY" != "yes" ]]; then
    die "Финальная проверка: public key authentication отключён."
fi

if [[ "$FINAL_USER" != "$SSH_USER" ]]; then
    die "Финальная проверка: AllowUsers настроен неправильно (эффективное значение: '$FINAL_USER')."
fi


# ============================================================
# 37. Успешное завершение
# ============================================================

echo ""

# Отключаем rollback после успешного завершения.
trap - EXIT

section "SSH SETUP COMPLETED"

echo ""
echo "SSH USER       : $SSH_USER"
echo "SSH PORT       : $SSH_PORT"
if (( PORT_RESERVED )); then
    echo "PORT RESERVED  : $SYSCTL_RESERVE_FILE"
fi
echo "ROOT LOGIN     : disabled"
echo "PASSWORD LOGIN : disabled"
echo "KEY LOGIN      : enabled"
echo "PORT 22        : disabled"
echo "UFW            : checked"
echo "SSH SOCKET     : checked"
echo ""
echo "SSH config:"
echo "$SSH_CONFIG"
echo ""
echo "SSH socket override:"
echo "$SOCKET_DROPIN"
echo ""
echo "Backup:"
echo "$CURRENT_BACKUP"
echo ""
echo "Rollback:"
echo "sudo $SCRIPT_NAME --rollback"
echo ""
echo "========================================="
echo ""
echo "!!! НЕ ЗАКРЫВАЙТЕ ТЕКУЩУЮ SSH-СЕССИЮ !!!"
echo ""
echo "Сначала проверьте новое подключение:"
echo ""
echo "ssh -p $SSH_PORT $SSH_USER@IP_СЕРВЕРА"
echo ""
echo "Только после успешного подключения"
echo "можно закрыть старую SSH-сессию."
echo ""
echo "========================================="
