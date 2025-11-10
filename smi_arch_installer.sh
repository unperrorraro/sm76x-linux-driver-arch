#!/bin/bash
export LC_ALL=C
readonly SELF=$0
readonly COREDIR=/opt/siliconmotion
readonly OTHERPDDIR=/opt/displaylink
readonly LOGPATH=/var/log/SMIUSBDisplay
readonly PRODUCT="Silicon Motion Linux USB Display Software"
VERSION=2.21.2.0
ACTION=install

# Arch Linux dependencies (pacman packages)
PACMAN_DEPENDENCIES=(dkms libusb libdrm pkgconf gcc make)

readonly PACMAN_DEPENDENCIES

detect_kernel_package() {
  # Detect which kernel package is installed
  if pacman -Qi linux-lts >/dev/null 2>&1; then
    echo "linux-lts-headers"
  elif pacman -Qi linux-zen >/dev/null 2>&1; then
    echo "linux-zen-headers"
  elif pacman -Qi linux-hardened >/dev/null 2>&1; then
    echo "linux-hardened-headers"
  elif pacman -Qi linux >/dev/null 2>&1; then
    echo "linux-headers"
  else
    # Fallback: try to detect from uname
    local KVER=$(uname -r)
    if [[ $KVER == *-lts* ]]; then
      echo "linux-lts-headers"
    elif [[ $KVER == *-zen* ]]; then
      echo "linux-zen-headers"
    elif [[ $KVER == *-hardened* ]]; then
      echo "linux-hardened-headers"
    else
      echo "linux-headers"
    fi
  fi
}

install_evdi() {
  TARGZ="$1"
  ERRORS="$2"
  local EVDI_DRM_DEPS
  local EVDI
  EVDI=$(mktemp -d)
  if ! tar xf "$TARGZ" -C "$EVDI"; then
    echo "Unable to extract $TARGZ to $EVDI" >"$ERRORS"
    return 1
  fi

  # Check if EVDI is already installed in DKMS
  local EVDI_VERSION
  EVDI_VERSION=$(awk -F '=' '/PACKAGE_VERSION/{print $2}' "${EVDI}/module/dkms.conf" 2>/dev/null | tr -d '"' | xargs)

  if dkms status evdi 2>/dev/null | grep -q "evdi.*installed"; then
    echo "[[ EVDI DKMS module already installed - checking version ]]"
    local INSTALLED_VERSION
    INSTALLED_VERSION=$(dkms status evdi 2>/dev/null | grep installed | head -n1 | sed -n 's/.*evdi[,\/]\([^,]*\),.*/\1/p' | xargs)
    echo "Installed EVDI version: $INSTALLED_VERSION"
    echo "Package EVDI version: $EVDI_VERSION"

    # Compare versions - if installed version is newer or equal, keep it
    if [ "$INSTALLED_VERSION" == "$EVDI_VERSION" ]; then
      echo "[[ EVDI version matches, skipping installation ]]"
      # Still need to configure module loading
      printf '%s\n' 'evdi' >/etc/modules-load.d/evdi.conf
      printf '%s\n' 'options evdi initial_device_count=4' >/etc/modprobe.d/evdi.conf

      # Backup module configuration
      local EVDI_SRC_VERSION
      EVDI_SRC_VERSION=$(ls -t /usr/src 2>/dev/null | grep evdi | head -n1)
      if [ -n "$EVDI_SRC_VERSION" ]; then
        cp -rf /usr/src/$EVDI_SRC_VERSION $COREDIR/module 2>/dev/null || true
        cp /etc/modprobe.d/evdi.conf $COREDIR 2>/dev/null || true
      fi

      rm -rf "$EVDI"
      return 0
    else
      echo "[[ WARNING: Installed EVDI version ($INSTALLED_VERSION) differs from package version ($EVDI_VERSION) ]]"
      echo "[[ The installed version may be newer and compatible with your kernel ]]"
      read -rp 'Do you want to keep the currently installed version? (Y/n) ' CHOICE
      if [[ ${CHOICE:-Y} =~ ^[Yy]$ ]]; then
        echo "[[ Keeping installed EVDI version ]]"
        # Configure module loading
        printf '%s\n' 'evdi' >/etc/modules-load.d/evdi.conf
        printf '%s\n' 'options evdi initial_device_count=4' >/etc/modprobe.d/evdi.conf

        # Backup module configuration
        local EVDI_SRC_VERSION
        EVDI_SRC_VERSION=$(ls -t /usr/src 2>/dev/null | grep evdi | head -n1)
        if [ -n "$EVDI_SRC_VERSION" ]; then
          cp -rf /usr/src/$EVDI_SRC_VERSION $COREDIR/module 2>/dev/null || true
          cp /etc/modprobe.d/evdi.conf $COREDIR 2>/dev/null || true
        fi

        rm -rf "$EVDI"
        return 0
      else
        echo "[[ Removing old EVDI version ]]"
        dkms remove -m evdi -v "$INSTALLED_VERSION" --all 2>/dev/null || true
        rm -rf "/usr/src/evdi-$INSTALLED_VERSION" 2>/dev/null || true
      fi
    fi
  fi

  echo "[[ Installing EVDI DKMS module ]]"
  (
    dkms install "${EVDI}/module"
    local retval=$?

    if [ $retval == 3 ]; then
      echo "EVDI DKMS module already installed."
    elif [ $retval != 0 ]; then
      echo "Failed to install evdi to the kernel tree." >"$ERRORS"
      echo "" >>"$ERRORS"
      echo "Build log location: /var/lib/dkms/evdi/$EVDI_VERSION/build/make.log" >>"$ERRORS"
      if [ -f "/var/lib/dkms/evdi/$EVDI_VERSION/build/make.log" ]; then
        echo "Last 20 lines of build log:" >>"$ERRORS"
        tail -n 20 "/var/lib/dkms/evdi/$EVDI_VERSION/build/make.log" >>"$ERRORS"
      fi
      echo "" >>"$ERRORS"
      echo "This usually means the EVDI version is incompatible with your kernel." >>"$ERRORS"
      echo "You may need to:" >>"$ERRORS"
      echo "1. Install a newer EVDI version from AUR: yay -S evdi" >>"$ERRORS"
      echo "2. Or downgrade your kernel to a compatible version" >>"$ERRORS"
      make -sC "${EVDI}/module" uninstall_dkms 2>/dev/null
      return 1
    fi
  ) || return 1

  echo "[[ Installing module configuration files ]]"
  printf '%s\n' 'evdi' >/etc/modules-load.d/evdi.conf

  printf '%s\n' 'options evdi initial_device_count=4' \
    >/etc/modprobe.d/evdi.conf
  EVDI_DRM_DEPS=$(sed -n -e '/^drm_kms_helper/p' /proc/modules | awk '{print $4}' | tr ',' ' ')
  EVDI_DRM_DEPS=${EVDI_DRM_DEPS/evdi/}

  [[ "${EVDI_DRM_DEPS}" ]] && printf 'softdep %s pre: %s\n' 'evdi' "${EVDI_DRM_DEPS}" \
    >>/etc/modprobe.d/evdi.conf

  echo "[[ Backing up EVDI DKMS module ]]"
  local EVDI_SRC_VERSION
  EVDI_SRC_VERSION=$(ls -t /usr/src 2>/dev/null | grep evdi | head -n1)
  if [ -n "$EVDI_SRC_VERSION" ]; then
    cp -rf /usr/src/$EVDI_SRC_VERSION $COREDIR/module
    cp /etc/modprobe.d/evdi.conf $COREDIR
  fi

  echo "[[ Installing EVDI library ]]"

  (
    cd "${EVDI}/library" || return 1

    if ! make; then
      echo "Failed to build evdi library." >"$ERRORS"
      return 1
    fi

    if ! cp -f libevdi.so "$COREDIR"; then
      echo "Failed to copy evdi library to $COREDIR." >"$ERRORS"
      return 1
    fi

    chmod 0755 "$COREDIR/libevdi.so"

    ln -sf "$COREDIR/libevdi.so" /usr/lib/libevdi.so.0
    ln -sf "$COREDIR/libevdi.so" /usr/lib/libevdi.so.1

  ) || return 1

  rm -rf "$EVDI"
}

uninstall_evdi_module() {
  TARGZ="$1"

  local EVDI
  EVDI=$(mktemp -d)
  if ! tar xf "$TARGZ" -C "$EVDI"; then
    echo "Unable to extract $TARGZ to $EVDI"
    return 1
  fi

  (
    cd "${EVDI}/module" || return 1
    make uninstall_dkms
  )
}

is_32_bit() {
  [ "$(getconf LONG_BIT)" == "32" ]
}

add_smi_script() {
  MODVER="$1"
  cat >/usr/share/X11/xorg.conf.d/20-smi.conf <<'EOF'
Section "Device"
        Identifier "SiliconMotion"
        Driver "modesetting"
	Option "PageFlip" "false"
EndSection
EOF

  chown root: /usr/share/X11/xorg.conf.d/20-smi.conf
  chmod 644 /usr/share/X11/xorg.conf.d/20-smi.conf

}

remove_smi_script() {
  rm -f /usr/share/X11/xorg.conf.d/20-smi.conf
}

add_systemd_service() {
  cat >/usr/lib/systemd/system/smiusbdisplay.service <<'EOF'
[Unit]
Description=SiliconMotion Driver Service
After=display-manager.service
Conflicts=getty@tty7.service

[Service]
ExecStartPre=/bin/bash -c "modprobe evdi || (dkms remove -m evdi -v $(awk -F '=' '/PACKAGE_VERSION/{print $2}' /opt/siliconmotion/module/dkms.conf) --all; if [ $? != 0 ]; then rm -rf /var/lib/dkms/$(awk -F '=' '/PACKAGE_VERSION/{print $2}' /opt/siliconmotion/module/dkms.conf) ;fi; dkms install /opt/siliconmotion/module/ && cp /opt/siliconmotion/evdi.conf /etc/modprobe.d && modprobe evdi)"

ExecStart=/opt/siliconmotion/SMIUSBDisplayManager
Restart=always
WorkingDirectory=/opt/siliconmotion
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  chmod 0644 /usr/lib/systemd/system/smiusbdisplay.service
}

trigger_udev_if_devices_connected() {
  for device in $(grep -lw 090c /sys/bus/usb/devices/*/idVendor 2>/dev/null); do
    udevadm trigger --action=add "$(dirname "$device")"
  done
}

remove_systemd_service() {
  driver_name="smiusbdisplay"
  echo "Stopping ${driver_name} systemd service"
  systemctl stop ${driver_name}.service 2>/dev/null
  systemctl disable ${driver_name}.service 2>/dev/null
  rm -f /usr/lib/systemd/system/${driver_name}.service
}

add_pm_script() {
  cat >$COREDIR/smipm.sh <<'EOF'
#!/bin/bash

suspend_usb()
{
# anything want to do for suspend
}

resume_usb()
{
# anything want to do for resume
}

case "$1/$2" in
  pre/*)
    suspend_usb
    ;;
  post/*)
    resume_usb
    ;;
esac
EOF

  chmod 0755 $COREDIR/smipm.sh
  ln -sf $COREDIR/smipm.sh /usr/lib/systemd/system-sleep/smipm.sh
}

remove_pm_scripts() {
  rm -f /usr/lib/systemd/system-sleep/smipm.sh
}

cleanup() {
  rm -rf $COREDIR
  rm -rf $LOGPATH
  rm -f /usr/bin/smi-installer
  rm -f /usr/bin/SMIFWLogCapture
  rm -f /etc/modprobe.d/evdi.conf
  rm -rf /etc/modules-load.d/evdi.conf
}

binary_location() {
  local PREFIX="x64"
  local POSTFIX="ubuntu"

  is_32_bit && PREFIX="x86"
  echo "$PREFIX-$POSTFIX"
}

install() {
  echo "Installing"
  mkdir -p $COREDIR
  chmod 0755 $COREDIR

  cp -f "$SELF" "$COREDIR"
  ln -sf "$COREDIR/$(basename "$SELF")" /usr/bin/smi-installer
  chmod 0755 /usr/bin/smi-installer

  echo "Installing EVDI"
  local ERRORS
  ERRORS=$(mktemp)
  finish() {
    rm -f "$ERRORS"
  }
  trap finish EXIT

  if ! install_evdi "evdi.tar.gz" "$ERRORS"; then
    echo "ERROR: $(<"$ERRORS")" >&2
    cleanup
    exit 1
  fi

  local BINS=$(binary_location)

  local SMI="$BINS/SMIUSBDisplayManager"
  local LIBUSB="$BINS/libusb-1.0.so.0.2.0"
  local GETFWLOG="$BINS/SMIFWLogCapture"

  cp -f 'evdi.tar.gz' "$COREDIR"
  echo "Installing $SMI"
  cp -f $SMI $COREDIR

  echo "Installing $GETFWLOG"
  cp -f $GETFWLOG $COREDIR

  echo "Installing libraries"
  [ -f $LIBUSB ] && cp -f $LIBUSB /usr/lib/libusb-1.0.so.0
  chmod 0755 /usr/lib/libusb-1.0.so.0
  [ -f $LIBUSB ] && cp -f $LIBUSB $COREDIR
  ln -sf $COREDIR/libusb-1.0.so.0.2.0 $COREDIR/libusb-1.0.so.0
  ln -sf $COREDIR/libusb-1.0.so.0.2.0 $COREDIR/libusb-1.0.so

  echo "Installing firmware packages"
  local BOOTLOADER0="Bootloader0.bin"
  local BOOTLOADER1="Bootloader1.bin"
  local FIRMWARE0BIN="firmware0.bin"
  local FIRMWARE1BIN="USBDisplay.bin"

  [ -f $BOOTLOADER0 ] && cp -f $BOOTLOADER0 $COREDIR
  [ -f $BOOTLOADER1 ] && cp -f $BOOTLOADER1 $COREDIR
  [ -f $FIRMWARE0BIN ] && cp -f $FIRMWARE0BIN $COREDIR
  [ -f $FIRMWARE1BIN ] && cp -f $FIRMWARE1BIN $COREDIR

  chmod 0755 $COREDIR/SMIUSBDisplayManager
  chmod 0755 $COREDIR/libusb*.so*
  chmod 0755 $COREDIR/SMIFWLogCapture

  ln -sf $COREDIR/SMIFWLogCapture /usr/bin/SMIFWLogCapture
  chmod 0755 /usr/bin/SMIFWLogCapture

  source smi-udev-installer.sh
  siliconmotion_bootstrap_script="$COREDIR/smi-udev.sh"
  create_bootstrap_file "$SYSTEMINITDAEMON" "$siliconmotion_bootstrap_script"

  echo "Adding udev rule for SiliconMotion devices"
  create_udev_rules_file /etc/udev/rules.d/99-smiusbdisplay.rules
  xorg_running || udevadm control -R
  xorg_running || udevadm trigger

  echo "Starting SMIUSBDisplay systemd service"
  add_systemd_service
  systemctl daemon-reload
  systemctl enable smiusbdisplay.service

  xorg_running || trigger_udev_if_devices_connected
  xorg_running || $siliconmotion_bootstrap_script START

  echo -e "\nInstallation complete!"
  echo -e "\nPlease reboot your computer if you're intending to use Xorg."
  xorg_running || exit 0
  read -rp 'Xorg is running. Do you want to reboot now? (Y/n)' CHOICE
  [[ ${CHOICE:-Y} =~ ^[Nn]$ ]] && exit 0
  reboot
}

uninstall() {
  echo "Uninstalling"

  echo "Stopping SMIUSBDisplay systemd service"
  systemctl stop smiusbdisplay.service 2>/dev/null
  remove_systemd_service

  echo "[ Removing suspend-resume hooks ]"
  remove_pm_scripts

  echo "[ Removing udev rule ]"
  rm -f /etc/udev/rules.d/99-smiusbdisplay.rules
  udevadm control -R
  udevadm trigger

  echo "[ Removing Core folder ]"
  cleanup

  modprobe -r evdi

  if [ -d $OTHERPDDIR ]; then
    echo "WARNING: There are other products in the system using EVDI."
  else
    echo "Removing EVDI from kernel tree, DKMS, and removing sources."
    (
      cd "$(dirname "$(realpath "${BASH_SOURCE[0]}")")" &&
        uninstall_evdi_module "evdi.tar.gz"
    )
  fi

  echo -e "\nUninstallation steps complete."
  if [ -f /sys/devices/evdi/count ]; then
    echo "Please note that the evdi kernel module is still in the memory."
    echo "A reboot is required to fully complete the uninstallation process."
  fi
}

missing_requirement() {
  echo "Unsatisfied dependencies. Missing component: $1." >&2
  echo "This is a fatal error, cannot install $PRODUCT." >&2
  exit 1
}

version_lt() {
  local left
  left=$(echo "$1" | cut -d. -f-2)
  local right
  right=$(echo "$2" | cut -d. -f-2)

  local greater
  greater=$(echo -e "$left\n$right" | sort -Vr | head -1)

  [ "$greater" != "$left" ]
}

program_exists() {
  command -v "${1:?}" >/dev/null 2>&1
}

check_installed_pacman() {
  pacman -Qi "${1:?}" >/dev/null 2>&1
}

install_dependencies() {
  program_exists pacman || return 0
  install_dependencies_pacman
}

pacman_ask_for_dependencies() {
  local packages=("$@")
  echo "The following packages will be installed:"
  printf '  %s\n' "${packages[@]}"
  echo ""
}

install_dependencies_pacman() {
  echo "[ Dependency check ]"
  local packages=()

  for item in "${PACMAN_DEPENDENCIES[@]}"; do
    check_installed_pacman "$item" || packages+=("$item")
  done

  # Detect and check for appropriate kernel headers
  local KERNEL_HEADERS=$(detect_kernel_package)
  echo "Detected kernel headers package: $KERNEL_HEADERS"

  if ! pacman -Qi "$KERNEL_HEADERS" >/dev/null 2>&1; then
    packages+=("$KERNEL_HEADERS")
  fi

  if [[ ${#packages[@]} -gt 0 ]]; then
    echo "[ Installing dependencies ]"
    pacman_ask_for_dependencies "${packages[@]}"

    read -rp 'Do you want to continue? [Y/n] ' CHOICE
    [[ "${CHOICE:-Y}" == "${CHOICE#[Yy]}" ]] && exit 0

    pacman -S --needed --noconfirm "${packages[@]}" || check_requirements
  fi
}

check_requirements() {
  # DKMS
  program_exists dkms || missing_requirement "DKMS"

  # libdrm
  check_installed_pacman libdrm || missing_requirement "libdrm"

  # Required kernel version
  KVER=$(uname -r)
  KVER_MIN="4.15"
  version_lt "$KVER" "$KVER_MIN" && missing_requirement "Kernel version $KVER is too old. At least $KVER_MIN is required"

  # Linux headers - check if they exist for the running kernel
  if [ ! -d "/lib/modules/$KVER/build" ]; then
    echo "Linux headers not found for running kernel: $KVER" >&2
    echo "Please install the appropriate headers package:" >&2
    local KERNEL_HEADERS=$(detect_kernel_package)
    echo "  sudo pacman -S $KERNEL_HEADERS" >&2
    missing_requirement "Linux headers for running kernel, $KVER"
  fi
}

usage() {
  echo
  echo "Installs $PRODUCT, version $VERSION."
  echo "Usage: $SELF [ install | uninstall ]"
  echo
  echo "The default operation is install."
  echo "If unknown argument is given, a quick compatibility check is performed but nothing is installed."
  exit 1
}

detect_init_daemon() {
  INIT=$(readlink /proc/1/exe)
  if [ "$INIT" == "/sbin/init" ]; then
    INIT=$(/sbin/init --version 2>/dev/null)
  fi

  if [[ $INIT == *systemd* ]] || [ -d /run/systemd/system ]; then
    SYSTEMINITDAEMON="systemd"
  else
    echo "ERROR: This script requires systemd." >&2
    echo "Arch Linux uses systemd by default." >&2
    echo "Installation terminated." >&2
    exit 1
  fi
}

detect_distro() {
  if [ -f /etc/arch-release ]; then
    echo "Distribution discovered: Arch Linux"
  elif program_exists lsb_release; then
    echo -n "Distribution discovered: "
    lsb_release -d -s
  else
    echo "WARNING: This is not an officially supported distribution." >&2
  fi
}

xorg_running() {
  local SESSION_NO
  SESSION_NO=$(loginctl 2>/dev/null | awk "/$(logname 2>/dev/null || echo root)/ {print \$1; exit}")
  [[ $(loginctl show-session "$SESSION_NO" -p Type 2>/dev/null) == *=x11 ]]
}

check_preconditions() {
  # Check if evdi module is already loaded
  if lsmod | grep -q "^evdi"; then
    echo "INFO: EVDI kernel module is already loaded." >&2

    if [ -d $COREDIR ]; then
      echo "WARNING: $PRODUCT appears to be already installed." >&2
      read -rp 'Do you want to reinstall? This will uninstall the current version first. (Y/n) ' CHOICE
      if [[ ${CHOICE:-Y} =~ ^[Yy]$ ]]; then
        echo "Uninstalling previous version..."
        uninstall
        echo "Proceeding with installation..."
      else
        echo "Installation cancelled." >&2
        exit 1
      fi
    elif [ -d $OTHERPDDIR ]; then
      echo "WARNING: There are other products in the system using EVDI (DisplayLink)." >&2
      echo "This installation will share the EVDI module with other products."
      read -rp 'Do you want to continue? (Y/n) ' CHOICE
      if [[ ! ${CHOICE:-Y} =~ ^[Yy]$ ]]; then
        echo "Installation cancelled." >&2
        exit 1
      fi
    fi
  fi
}

if [ "$(id -u)" != "0" ]; then
  echo "You need to be root to use this script." >&2
  exit 1
fi

echo "$PRODUCT $VERSION install script called: $*"
[ -z "$SYSTEMINITDAEMON" ] && detect_init_daemon || echo "Trying to use the forced init system: $SYSTEMINITDAEMON"
detect_distro

while [ -n "$1" ]; do
  case "$1" in
  install)
    ACTION="install"
    ;;
  uninstall)
    ACTION="uninstall"
    ;;
  *)
    usage
    ;;
  esac
  shift
done

if [ "$ACTION" == "install" ]; then
  install_dependencies
  check_requirements
  check_preconditions
  install
elif [ "$ACTION" == "uninstall" ]; then
  check_requirements
  uninstall
fi
