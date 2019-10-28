#!/usr/bin/env bash

usage() {
	local old_xtrace
	old_xtrace="$(shopt -po xtrace || :)"
	set +o xtrace
	echo "${script_name} - Create or start a Debian QEMU installation." >&2
	echo "Usage: ${script_name} [flags]" >&2
	echo "Option flags:" >&2
	echo "  -c --check       - Run shellcheck." >&2
	echo "  -h --help        - Show this help and exit." >&2
	echo "  -v --verbose     - Verbose execution." >&2
	echo "  --hostfwd        - QEMU ssh hostfwd port. Default: '${hostfwd}'." >&2
	echo "  --p9-share       - Plan9 share directory. Default: '${p9_share}'." >&2
	echo "  --install-distro - Create new disk image, run installer (about 50 minutes)." >&2
	echo "                     {${known_distros}}. Default: '${install_distro}'." >&2
	echo "  --install-dir    - Installation directory. Default: '${install_dir}'." >&2
	echo "  --keep-tmp       - Keep temp files." >&2
	eval "${old_xtrace}"
}

process_opts() {
	local short_opts="chvk"
	local long_opts="check,help,verbose,\
hostfwd:,p9-share:,install-distro:,install-dir:,keep-tmp"

	local opts
	opts=$(getopt --options ${short_opts} --long ${long_opts} -n "${script_name}" -- "$@")

	eval set -- "${opts}"

	while true ; do
		#echo "${FUNCNAME[0]}: @${1}@ @${2}@"
		case "${1}" in
		-c | --check)
			check=1
			shift
			;;
		-h | --help)
			usage=1
			shift
			;;
		-v | --verbose)
			verbose=1
			set -x
			shift
			;;
		--hostfwd)
			hostfwd="${2}"
			shift 2
			;;
		--p9-share)
			p9_share="${2}"
			shift 2
			;;
		--install-distro)
			install_distro="${2}"
			shift 2
			;;
		--install-dir)
			install_dir="${2}"
			shift 2
			;;
		--keep-tmp)
			keep_tmp=1
			shift
			;;
		--)
			shift
			break
			;;
		*)
			echo "${script_name}: ERROR: Internal opts: '${*}'" >&2
			exit 1
			;;
		esac
	done
}

on_exit() {
	local result=${1}

	if [[ ${install_dir} ]]; then
		echo "${script_name}: INFO: Install directory: '${install_dir}'" >&2
	fi

	if [[ -d "${tmp_dir}" ]]; then
		if [[ ${keep_tmp} ]]; then
			echo "${script_name}: INFO: tmp directory: '${tmp_dir}'" >&2
		else
			rm -rf "${tmp_dir}"
		fi
	fi

	echo "${script_name}: Done: ${result}." >&2
}

check_file() {
	local src="${1}"
	local msg="${2}"
	local usage="${3}"

	if [[ ! -f "${src}" ]]; then
		echo -e "${script_name}: ERROR: File not found${msg}: '${src}'" >&2
		[[ -z "${usage}" ]] || usage
		exit 1
	fi
}

check_directory() {
	local src="${1}"
	local msg="${2}"
	local usage="${3}"

	if [[ ! -d "${src}" ]]; then
		echo "${script_name}: ERROR (${FUNCNAME[0]}): Directory not found${msg}: '${src}'" >&2
		[[ -z "${usage}" ]] || usage
		exit 1
	fi
}

check_sum() {
	local local_dir=${1}
	local remote_dir=${2}
	local file=${3}

	local sum1
	local sum2

	sum1=$(md5sum "${local_dir}/${file}" | cut -f 1 -d ' ')
	sum2=$(grep -E "/${remote_dir}/${file}" "${local_dir}/MD5SUMS" | cut -f 1 -d ' ')

	echo "${file} sum1: ${sum1}"
	echo "${file} sum2: ${sum2}"
	
	if [[ "${sum1}" != "${sum2}" ]]; then
		echo "${script_name}: ERROR: Bad ${file} sum" >&2
		exit 1
	fi
}

run_qemu() {
	local host_name=${1}
	local pid_file=${2}
	local hostfwd=${3}
	local hda=${4}
	local efi_code=${5}
	local efi_vars=${6}
	local kernel=${7}
	local initrd=${8}
	local append=${9}

	qemu-system-aarch64 \
		-name "${host_name}" \
		-pidfile "${pid_file}" \
		-machine virt,gic-version=3 \
		-cpu cortex-a57 \
		-m 5120 \
		-smp 2 \
		-nographic \
		-object rng-random,filename=/dev/urandom,id=rng0 \
		-device virtio-rng-pci,rng=rng0 \
		-netdev user,id=eth0,hostfwd=tcp::"${hostfwd}"-:22,hostname="${host_name}" \
		-device virtio-net-device,netdev=eth0 \
		-drive if=pflash,file="${efi_code}",format=raw,readonly \
		-drive if=pflash,file="${efi_vars}",format=raw \
		-hda "${hda}" \
		${qemu_extra_args:+${qemu_extra_args}} \
		${kernel:+-kernel ${kernel}} \
		${initrd:+-initrd ${initrd}} \
		${append:+-append ${append}}
}

extract_initrd() {
	local initrd_file=${1}
	local out_dir=${2}
	
	rm -rf "${out_dir}"
	mkdir -p "${out_dir}"

	(cd "${out_dir}" && gunzip < "${initrd_file}" | ${sudo} cpio --extract --make-directories --preserve-modification-time)
	${sudo} chown -R "${USER}": "${out_dir}"
}

create_initrd() {
	local in_dir=${1}
	local initrd_file=${2}

	(cd "${in_dir}" && ${sudo} find . | ${sudo} cpio --create --format='newc' --owner=root:root | gzip) > "${initrd_file}"
}

installer_download() {
	local tmp_dir="${1}"
	local remote_dir=${2}
	local files_url=${3}
	local sums_url=${4}

	local no_verbose
	[[ ${verbose} ]] || no_verbose="--no-verbose"

	# For debugging.
	if [[ -d "/tmp/download-file-cache" ]]; then
		cp -av "/tmp/download-file-cache/"* "${tmp_dir}/"
	else
		wget ${no_verbose} \
			-O "${tmp_dir}/MD5SUMS" "${sums_url}/MD5SUMS"
		wget ${no_verbose} \
			-O "${tmp_dir}/initrd.gz" "${files_url}/initrd.gz"
		wget ${no_verbose} \
			-O "${tmp_dir}/linux" "${files_url}/linux"
	fi

	check_sum "${tmp_dir}" "${remote_dir}" "initrd.gz"
	check_sum "${tmp_dir}" "${remote_dir}" "linux"
}

debian_download() {
	local tmp_dir="${1}"
	local release="${2}"

	local version="current"
	local remote_dir="netboot/debian-installer/arm64"
	local files_url="http://ftp.nl.debian.org/debian/dists/${release}/main/installer-arm64/${version}/images/${remote_dir}"
	local sums_url="http://ftp.nl.debian.org/debian/dists/${release}/main/installer-arm64/${version}/images/"

	installer_download "${tmp_dir}" "${remote_dir}" "${files_url}" "${sums_url}"
}

ubuntu_download() {
	local tmp_dir="${1}"
	local release="${2}"

	local version="current"
	local remote_dir="netboot/ubuntu-installer/arm64"
	local files_url="http://ports.ubuntu.com/ubuntu-ports/dists/${release}/main/installer-arm64/${version}/images/${remote_dir}"
	local sums_url="http://ports.ubuntu.com/ubuntu-ports/dists/${release}/main/installer-arm64/${version}/images/"

	installer_download "${tmp_dir}" "${remote_dir}" "${files_url}" "${sums_url}"
}

initrd_add_preseed() {
	local initrd_file=${1}
	local preseed_file=${2}
	local work_dir="${tmp_dir}/initrd-files"

	extract_initrd "${initrd_file}" "${work_dir}"
	cp -fv "${preseed_file}" "${work_dir}/preseed.cfg"
	cp -v "${initrd_file}" "${tmp_dir}/initrd.bak"
	create_initrd "${work_dir}" "${initrd_file}"
}

preseed_show_creds() {
	local preseed=${1}

	local user
	local pw

	user=$(grep -E 'd-i passwd/username string' < "${preseed}")
	pw=$(grep -E 'd-i passwd/user-password password' < "${preseed}")

	echo "${script_name}: INFO: preseed user: '${user##* }'" >&2
	echo "${script_name}: INFO: preseed password: '${pw##* }'" >&2
}

run_installer() {
	distro=${1}
	release=${2}

	tmp_dir="$(mktemp --tmpdir --directory "${script_name}"-tmp.XXXX)"

	case "${distro}" in
	debian)
		;;
	ubuntu)
		;;
	*)
		echo "${script_name}: ERROR: Unknown distro: '${distro}'" >&2
		exit 1
		;;
	esac

	local install_dir="${install_dir:-"/tmp/${script_name}-${distro}-${build_time}"}"
	mkdir -p "${install_dir}"
	
	"${distro}"_download "${tmp_dir}" "${release}"
	
	disk_image="${disk_image:-"${install_dir}/hda.qcow2"}"

	efi_code_src=${efi_code_src:-"/usr/share/AAVMF/AAVMF_CODE.fd"}
	efi_vars_src=${efi_vars_src:-"/usr/share/AAVMF/AAVMF_VARS.fd"}

	check_file "${efi_code_src}"
	check_file "${efi_vars_src}"

	cp -av "${efi_code_src}" "${install_dir}/efi-code"
	cp -av "${efi_code_src}" "${install_dir}/efi-vars"

	preseed_file=${preseed_file:-"${SCRIPTS_TOP}/${distro}-qemu.preseed"}

	if [[ ! -f "${preseed_file}" ]]; then
		echo "${script_name}: INFO: No preseed file found: '${preseed_file}'" >&2
	else
		check_file "${preseed_file}"
		cp -av "${preseed_file}" "${install_dir}/"
		initrd_add_preseed "${tmp_dir}/initrd.gz" "${preseed_file}"
	fi

	qemu-img create -f qcow2 "${disk_image}" 80G

	qemu_extra_args+="-no-reboot"

	run_qemu \
		"${distro}-aarch64" \
		"${install_dir}/qemu-pid" \
		"${hostfwd}" \
		"${disk_image}" \
		"${install_dir}/efi-code" \
		"${install_dir}/efi-vars" \
		"${tmp_dir}/linux" \
		"${tmp_dir}/initrd.gz" \
		"text"

	echo "${script_name}: INFO: Install directory: '${install_dir}'" >&2
	if [[ -f "${preseed_file}" ]]; then
		preseed_show_creds "${preseed_file}"
	fi
}


start_vm() {
	local host_name=${1}

	disk_image="${disk_image:-"${install_dir}/hda.qcow2"}"

	check_directory "${install_dir}"     " <install-dir>" "usage"
	check_file "${disk_image}"           " <disk-image>"  "usage"
	check_file "${install_dir}/efi-code" " efi-code"      "usage"
	check_file "${install_dir}/efi-vars" " efi-vars"      "usage"

	if [[ ${p9_share} ]]; then
		check_directory "${p9_share}"
		P9_SHARE_ID=${P9_SHARE_ID:-"p9_share"}
		qemu_extra_args+="-virtfs local,id=${P9_SHARE_ID},path=${p9_share},security_model=none,mount_tag=${P9_SHARE_ID}"
		echo "${script_name}: INFO: 'mount -t 9p -o trans=virtio ${P9_SHARE_ID} <mount-point> -oversion=9p2000.L'" >&2
	fi

	local ssh_no_check="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

	echo "${script_name}: INFO: 'ssh ${ssh_no_check} -p ${hostfwd} <user>@localhost'" >&2

	run_qemu \
		"${host_name}" \
		"${install_dir}/qemu-pid" \
		"${hostfwd}" \
		"${disk_image}" \
		"${install_dir}/efi-code" \
		"${install_dir}/efi-vars"
}

#===============================================================================
export PS4='\[\033[0;33m\]+ ${BASH_SOURCE##*/}:${LINENO}:(${FUNCNAME[0]:-"?"}): \[\033[0;37m\]'
script_name="${0##*/}"
build_time="$(date +%Y.%m.%d-%H.%M.%S)"

trap "on_exit 'Failed'" EXIT
set -e

SCRIPTS_TOP=${SCRIPTS_TOP:-"$(cd "${BASH_SOURCE%/*}" && pwd)"}

process_opts "${@}"

known_distros="debian-sid debian-buster ubuntu-eoan ubuntu-bionic-updates"

hostname=${hostname:-"tester-aarch64"}
hostfwd=${hostfwd:-"20022"}
install_distro=${install_distro:-"debian-buster"}

sudo="sudo -S"

if [[ ${usage} ]]; then
	usage
	trap - EXIT
	exit 0
fi

if [[ ${check} ]]; then
	shellcheck=${shellcheck:-"shellcheck"}

	if ! test -x "$(command -v "${shellcheck}")"; then
		echo "${script_name}: ERROR: Please install '${shellcheck}'." >&2
		exit 1
	fi

	${shellcheck} "${0}"
	trap "on_exit 'Success'" EXIT
	exit 0
fi

if [[ ${install_distro} ]]; then
	distro="${install_distro%%-*}"
	release="${install_distro#*-}"

	run_installer "${distro}" "${release}"
	trap "on_exit 'Success'" EXIT
	exit 0
fi

start_vm "${hostname}"

trap "on_exit 'Success'" EXIT
exit 0
