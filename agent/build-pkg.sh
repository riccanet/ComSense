#!/bin/sh
#
# Build pfSense-pkg-ComSense-<version>.pkg without a ports tree.
#
# Run on FreeBSD (matching the target's major version) or directly on a
# pfSense box, both of which ship pkg(8):
#
#   sh build-pkg.sh                 # writes ./dist/pfSense-pkg-ComSense-<ver>.pkg
#   sh build-pkg.sh -a FreeBSD:15:amd64   # e.g. for pfSense Plus 24.x
#
# For official repositories, build the port in pfSense-pkg-ComSense/ with
# poudriere instead.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
PORT="${HERE}/pfSense-pkg-ComSense"
FILES="${PORT}/files"
NAME=pfSense-pkg-ComSense
VERSION=$(awk '/^PORTVERSION=/ {print $2}' "${PORT}/Makefile")
ABI=""

while getopts "a:" opt; do
	case "${opt}" in
		a) ABI="${OPTARG}" ;;
		*) echo "usage: $0 [-a ABI]" >&2; exit 2 ;;
	esac
done
if [ -z "${ABI}" ]; then
	# Packages are architecture independent; match only the OS major version.
	ABI="$(pkg config ABI | cut -d: -f1-2):*"
fi

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
STAGE="${WORK}/stage"
PREFIX=/usr/local
DATADIR="${PREFIX}/share/${NAME}"

install -d -m 0755 "${STAGE}${PREFIX}/pkg/comsense/lib" "${STAGE}${PREFIX}/sbin" \
	"${STAGE}${PREFIX}/www" "${STAGE}/etc/inc/priv" "${STAGE}${DATADIR}"
install -m 0644 "${FILES}${PREFIX}/pkg/comsense.xml" "${FILES}${PREFIX}/pkg/comsense.inc" "${STAGE}${PREFIX}/pkg/"
install -m 0644 "${FILES}${PREFIX}/pkg/comsense/agent.php" "${STAGE}${PREFIX}/pkg/comsense/"
install -m 0644 "${FILES}${PREFIX}"/pkg/comsense/lib/*.inc "${STAGE}${PREFIX}/pkg/comsense/lib/"
install -m 0755 "${FILES}${PREFIX}/sbin/comsense-agentd" "${FILES}${PREFIX}/sbin/comsense-watchdogd" "${STAGE}${PREFIX}/sbin/"
install -m 0644 "${FILES}${PREFIX}/www/comsense_status.php" "${STAGE}${PREFIX}/www/"
install -m 0644 "${FILES}/etc/inc/priv/comsense.priv.inc" "${STAGE}/etc/inc/priv/"
install -m 0644 "${FILES}${DATADIR}/info.xml" "${STAGE}${DATADIR}/"
sed -i '' -e "s|%%PKGVERSION%%|${VERSION}|" "${STAGE}${DATADIR}/info.xml" "${STAGE}${PREFIX}/pkg/comsense.xml"

sed -e "s|%%PORTNAME%%|${NAME}|g" "${FILES}/pkg-install.in" > "${WORK}/post-install"
sed -e "s|%%PORTNAME%%|${NAME}|g" "${FILES}/pkg-deinstall.in" > "${WORK}/pre-deinstall"

PLIST="${WORK}/plist"
( cd "${STAGE}" && find . -type f | sed -e 's|^\.||' | sort ) > "${PLIST}"

{
	echo "name: \"${NAME}\""
	echo "version: \"${VERSION}\""
	echo "origin: \"sysutils/${NAME}\""
	echo "comment: \"ComSense Firewall Manager agent for pfSense\""
	echo "desc: <<EOD"
	cat "${PORT}/pkg-descr"
	echo "EOD"
	echo "maintainer: \"https://github.com/riccanet/ComSense/issues\""
	echo "www: \"https://github.com/riccanet/ComSense\""
	echo "prefix: \"/\""
	echo "abi: \"${ABI}\""
	echo "licenselogic: \"single\""
	echo "licenses: [\"APACHE20\"]"
	echo "categories: [\"sysutils\"]"
	# Listed under System > Package Manager > Installed Packages (only shown for repository "pfSense").
	echo "annotations: { repository: \"pfSense\" }"
	echo "scripts: {"
	echo "  post-install: <<EOS"
	sed -e '1d' -e 's/\${2}/POST-INSTALL/' "${WORK}/post-install"
	echo "EOS"
	echo "  pre-deinstall: <<EOS"
	sed -e '1d' -e 's/\${2}/DEINSTALL/' "${WORK}/pre-deinstall"
	echo "EOS"
	echo "}"
} > "${WORK}/+MANIFEST"

mkdir -p "${HERE}/dist"
pkg create -M "${WORK}/+MANIFEST" -p "${PLIST}" -r "${STAGE}" -o "${HERE}/dist"
echo "Built ${HERE}/dist/${NAME}-${VERSION}.pkg (ABI ${ABI})"
