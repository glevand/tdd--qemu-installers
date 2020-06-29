#!/usr/bin/env bash

usage() {
	local old_xtrace
	old_xtrace="$(shopt -po xtrace || :)"
	set +o xtrace
	echo "${script_name} - Create or start a QEMU installation." >&2
	echo "Usage: ${script_name} [flags]" >&2
	echo "Option flags:" >&2
	echo "  -h --help        - Show this help and exit." >&2
	echo "  -v --verbose     - Verbose execution." >&2
	echo "  --arch           - Target architecture {${known_arches}}. Default: '${target_arch}'." >&2
	echo "  --hostfwd        - QEMU ssh hostfwd port. Default: '${hostfwd}'." >&2
	echo "  --p9-share       - Plan9 share directory. Default: '${p9_share}'." >&2
	echo "  --install-distro - Create new disk image, run installer (about 50 minutes)." >&2
	echo "                     {${known_distros}}". >&2
	echo "                     Default: '${install_distro}'." >&2
	echo "  --install-dir    - Installation directory. Default: '${install_dir}'." >&2
	echo "  --cache-dir      - Download file cache. Default: '${cache_dir}'." >&2
	echo "  --clean-tmp      - Remove temp files." >&2
	
	echo "Info:" >&2
	if [[ -d  "${cache_dir}" ]]; then
		if compgen -G "${cache_dir}/debian-installer_*_powerpc.buildinfo" > /dev/null; then
			echo "File cache '${cache_dir}' found." >&2
		else
			echo "File cache '${cache_dir}' empty." >&2
			exit 1
		fi
	else
		echo "File cache '${cache_dir}' not found." >&2
	fi
	eval "${old_xtrace}"
}

process_opts() {
	local short_opts="hvk"
	local long_opts="help,verbose,\
arch:,hostfwd:,p9-share:,install-distro:,install-dir:,cache-dir:,clean-tmp"

	local opts
	opts=$(getopt --options ${short_opts} --long ${long_opts} -n "${script_name}" -- "$@")

	eval set -- "${opts}"

	while true ; do
		#echo "${FUNCNAME[0]}: @${1}@ @${2}@"
		case "${1}" in
		-h | --help)
			usage=1
			shift
			;;
		-v | --verbose)
			verbose=1
			set -x
			shift
			;;
		--arch)
			target_arch=$(get_arch "${2}")
			shift 2
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
		--cache-dir)
			cache_dir="${2}"
			shift 2
			;;
		--clean-tmp)
			clean_tmp=1
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
		if [[ ${clean_tmp} ]]; then
			rm -rf "${tmp_dir}"
		else
			echo "${script_name}: INFO: tmp directory: '${tmp_dir}'" >&2
		fi
	fi

	echo "${script_name}: Done: ${result}." >&2
}

get_arch() {
	local a=${1}

	case "${a}" in
	arm64|aarch64)			echo "arm64" ;;
	amd64|x86_64)			echo "amd64" ;;
	ppc|powerpc|ppc32|powerpc32)	echo "powerpc" ;;
	ppc64|powerpc64)		echo "ppc64" ;;
	ppc64le|powerpc64le)		echo "ppc64le" ;;
	*)
		echo "${script_name}: ERROR (${FUNCNAME[0]}): Bad arch '${a}'" >&2
		exit 1
		;;
	esac
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

check_file_md5sum() {
	local file=${1}
	local sum=${2}

	local file_sum
	file_sum=$(md5sum "${file}" | cut -f 1 -d ' ')

	echo "${file}:"
	echo "  file sum:  ${file_sum}"
	echo "  check sum: ${sum}"
	
	if [[ "${file_sum}" != "${sum}" ]]; then
		echo "${script_name}: ERROR: Bad md5sum: '${file}'" >&2
		exit 1
	fi
}

check_installer_image_sum() {
	local info_file="${1}"
	local image_gz="${2}"

	# 18cde179c3be2916d70e57d1354fbd4b 130949912 debian-installer-images_20200314_powerpc.tar.gz

	local sum
	sum="$(grep -E "^ [[:xdigit:]]{32} [[:digit:]]* ${image_gz##*/}$" "${info_file}" | cut -d ' ' -f 2)"
	#echo "@${sum}@"

	check_file_md5sum "${image_gz}" "${sum}"
}

extract_initrd() {
	local initrd_file=${1}
	local out_dir=${2}
	
	rm -rf "${out_dir}"
	mkdir -p "${out_dir}"

	${sudo} true
	(cd "${out_dir}" && gunzip < "${initrd_file}" | ${sudo} cpio --extract --make-directories --preserve-modification-time)
	${sudo} chown -R "${USER}": "${out_dir}"
}

create_initrd() {
	local in_dir=${1}
	local initrd_file=${2}

	${sudo} true
	(cd "${in_dir}" && ${sudo} find . | ${sudo} cpio --create --format='newc' --owner=root:root | gzip) > "${initrd_file}"
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

setup_disk_images() {
	local install_dir=${1}
	local disk_image=${2}
	local preseed_file=${3}

	qemu-img create -f qcow2 "${disk_image}" 80G

	if [[ ! -f "${preseed_file}" ]]; then
		echo "${script_name}: WARNING: No preseed file found: '${preseed_file}'" >&2
	else
		check_file "${preseed_file}"
		cp -av "${preseed_file}" "${install_dir}/"
		initrd_add_preseed "${tmp_dir}/initrd.gz" "${preseed_file}"
	fi
}

check_target_arch() {
	local target_arch=${1}

	if [[ "${known_arches}" != *"${target_arch}"* ]]; then
		echo "${script_name}: ERROR: Unsupported target arch: '${target_arch}'." >&2
		usage
		exit 1
	fi
}

set_qemu_args() {
	case "${host_arch}--${target_arch}" in
	amd64--amd64)
		have_efi=1
		qemu_exe="qemu-system-x86_64"
		qemu_args+=" -machine accel=kvm -cpu host -m 2048 -smp 2"
		;;
	arm64--amd64)
		have_efi=1
		qemu_exe="qemu-system-x86_64"
		qemu_args+=" -machine pc-q35-2.8 -cpu kvm64 -m 2048 -smp 2"
		;;
	amd64--arm64)
		have_efi=1
		qemu_exe="qemu-system-aarch64"
		#qemu_mem=${qemu_mem:-5120} # 5G
		qemu_mem=${qemu_mem:-6144} # 6G
		#qemu_mem=${qemu_mem:-16384} # 16G
		qemu_args+=" -machine virt,gic-version=3 -cpu cortex-a57 -m ${qemu_mem} -smp 2"
		;;
	arm64--arm64)
		have_efi=1
		qemu_exe="qemu-system-aarch64"
		qemu_args+=" -machine virt,gic-version=3,accel=kvm -cpu host -m 4096 -smp 2"
		;;
	amd64--ppc*)
		unset have_efi
		qemu_exe="qemu-system-ppc64"
		#qemu_args+=" -machine cap-htm=off -m 2048"
		#qemu_args+=" -machine pseries,cap-htm=off -m 2048"
		qemu_args+=" -machine pseries,cap-htm=off -m 2048 -append 'root=/dev/ram0 console=hvc0'"
		;;
	amd64--powerpc)
		unset have_efi
		qemu_exe="qemu-system-ppc"
		qemu_args+=" -M mac99,via=pmu -L pc-bios -m 1024 -net nic,model=sungem -net user"
		;;
	*)
		echo "${script_name}: ERROR: Unsupported host--target combo: '${host_arch}--${target_arch}'." >&2
		exit 1
		;;
	esac
}

arm64_installer_download() {
	local tmp_dir="${1}"
	local remote_dir=${2}
	local files_url=${3}
	local sums_url=${4}

	local no_verbose
	[[ ${verbose} ]] || no_verbose="--no-verbose"

	# For debugging.
	if [[ -d "${cache_dir}" ]]; then
		cp -av "${cache_dir}/"* "${tmp_dir}/"
	else
		wget ${no_verbose} \
			-O "${tmp_dir}/MD5SUMS" "${sums_url}/MD5SUMS"
		wget ${no_verbose} \
			-O "${tmp_dir}/initrd.gz" "${files_url}/initrd.gz"
		wget ${no_verbose} \
			-O "${tmp_dir}/linux" "${files_url}/linux"
	fi

	local check_sum

	check_sum=$(grep -E "/${remote_dir}/initrd.gz" "${tmp_dir}/MD5SUMS" | cut -f 1 -d ' ')
	check_file_md5sum "${tmp_dir}/initrd.gz" "${check_sum}"

	check_sum=$(grep -E "/${remote_dir}/linux" "${tmp_dir}/MD5SUMS" | cut -f 1 -d ' ')
	check_file_md5sum "${tmp_dir}/linux" "${check_sum}"
}

arm64_debian_download() {
	local tmp_dir="${1}"
	local release="${2}"

	local version="current"
	local remote_dir="netboot/debian-installer/arm64"
	local files_url="http://ftp.nl.debian.org/debian/dists/${release}/main/installer-arm64/${version}/images/${remote_dir}"
	local sums_url="http://ftp.nl.debian.org/debian/dists/${release}/main/installer-arm64/${version}/images/"

	arm64_installer_download "${tmp_dir}" "${remote_dir}" "${files_url}" "${sums_url}"
}

arm64_ubuntu_download() {
	local tmp_dir="${1}"
	local release="${2}"

	local version="current"
	local remote_dir="netboot/ubuntu-installer/arm64"
	local files_url="http://ports.ubuntu.com/ubuntu-ports/dists/${release}/main/installer-arm64/${version}/images/${remote_dir}"
	local sums_url="http://ports.ubuntu.com/ubuntu-ports/dists/${release}/main/installer-arm64/${version}/images/"

	arm64_installer_download "${tmp_dir}" "${remote_dir}" "${files_url}" "${sums_url}"
}

arm64_run_qemu() {
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

arm64_installer_run() {
	local install_dir=${1}
	local distro=${2}
	local release=${3}

	distro_triple="${target_arch}-${install_distro}"

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

	${target_arch}_${distro}_download "${tmp_dir}" "${release}"

	disk_image="${disk_image:-"${install_dir}/${distro_triple}.qcow2"}"
	local preseed_file=${preseed_file:-"${SCRIPTS_TOP}/${distro_triple}-qemu.preseed"}

	setup_disk_images "${install_dir}" "${disk_image}" "${preseed_file}"

	efi_code_src=${efi_code_src:-"/usr/share/AAVMF/AAVMF_CODE.fd"}
	efi_vars_src=${efi_vars_src:-"/usr/share/AAVMF/AAVMF_VARS.fd"}

	check_file "${efi_code_src}"
	check_file "${efi_vars_src}"

	cp -av "${efi_code_src}" "${install_dir}/efi-code"
	cp -av "${efi_code_src}" "${install_dir}/efi-vars"

	qemu_extra_args+="-no-reboot"

	arm64_run_qemu \
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

arm64_start_vm() {
	local install_dir=${1}
	local host_name=${2}

	disk_image="${disk_image:-"${install_dir}/hda.qcow2"}"

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

	arm64_run_qemu \
		"${host_name}" \
		"${install_dir}/qemu-pid" \
		"${hostfwd}" \
		"${disk_image}" \
		"${install_dir}/efi-code" \
		"${install_dir}/efi-vars"
}

powerpc_installer_download() {
	local tmp_dir="${1}"

	local di_url="http://ftp.ports.debian.org/debian-ports/pool-powerpc/main/d/debian-installer/"
	local di_list="${tmp_dir}/list.html"

	curl -s -o "${di_list}" "${di_url}"
	version="$(egrep --only-matching '>debian-installer_[0-9]*_powerpc.buildinfo</a>' "${di_list}" | cut -d '_' -f 2)"
	echo "${script_name}: INFO: di version = '${version}'" >&2

	local di_info="debian-installer_${version}_powerpc.buildinfo"
	local di_tgz="debian-installer-images_${version}_powerpc.tar.gz"

	local no_verbose
	[[ ${verbose} ]] || no_verbose="--no-verbose"

	# For debugging.
	if [[ -d "${cache_dir}" ]]; then
		cp -av "${cache_dir}/"* "${tmp_dir}/"
	else
		wget ${no_verbose} \
			-O "${tmp_dir}/${di_info}" "${di_url}/${di_info}"
		wget ${no_verbose} \
			-O "${tmp_dir}/${di_tgz}" "${di_url}/${di_tgz}"
	fi

	check_installer_image_sum "${tmp_dir}/${di_info}" "${tmp_dir}/${di_tgz}"

	tar -C "${tmp_dir}" -xf "${tmp_dir}/${di_tgz}"

	cp -av --link "${tmp_dir}/installer-powerpc/${version}/images/netboot/debian-installer/powerpc/initrd.gz" \
		"${tmp_dir}/initrd.gz"
	cp -av --link "${tmp_dir}/installer-powerpc/${version}/images/netboot/debian-installer/powerpc/vmlinux" \
		"${tmp_dir}/linux"

}

powerpc_installer_run() {
	local install_dir=${1}
	local distro=${2}
	local release=${3}

	distro_triple="${target_arch}-${install_distro}"

	case "${distro}" in
	debian)
		;;
	*)
		echo "${script_name}: ERROR: Unknown distro: '${distro}'" >&2
		exit 1
		;;
	esac

	powerpc_installer_download "${tmp_dir}"

	disk_image="${disk_image:-"${install_dir}/hda.qcow2"}"
	local preseed_file=${preseed_file:-"${SCRIPTS_TOP}/${distro_triple}-qemu.preseed"}

	setup_disk_images "${install_dir}" "${disk_image}" "${preseed_file}"

#echo "${script_name}: INFO: initrd ready: '"${tmp_dir}/initrd.gz"'" >&2
#return
	qemu-system-ppc \
		-M mac99,via=pmu \
		-L pc-bios \
		-net nic,model=sungem \
		-net user \
		-object rng-random,filename=/dev/urandom,id=rng0 \
		-device virtio-rng-pci,rng=rng0 \
		-nographic \
		-m 1024 \
		-hda "${disk_image}" \
		-kernel "${tmp_dir}/linux" \
		-initrd "${tmp_dir}/initrd.gz" \
		-append "text"
}

#===============================================================================
export PS4='\[\e[0;33m\]+ ${BASH_SOURCE##*/}:${LINENO}:(${FUNCNAME[0]:-"?"}):\[\e[0m\] '
script_name="${0##*/}"
build_time="$(date +%Y.%m.%d-%H.%M.%S)"

trap "on_exit 'Failed'" EXIT
set -e

SCRIPTS_TOP="${SCRIPTS_TOP:-$(cd "${BASH_SOURCE%/*}" && pwd)}"

process_opts "${@}"

known_arches="arm64 powerpc"
known_distros="debian-sid debian-buster ubuntu-eoan ubuntu-bionic-updates"

host_arch="$(get_arch "$(uname -m)")"
target_arch="${target_arch:-${host_arch}}"

install_distro="${install_distro:-debian-buster}"
distro_triple="${target_arch}-${install_distro}"
cache_dir="${cache_dir:-/tmp/${distro_triple}-file-cache}"

hostname="${hostname:-tester-${target_arch}}"
hostfwd="${hostfwd:-20022}"

install_dir="${install_dir:-$(pwd)/${script_name%.sh}--${distro_triple}-${build_time}}"
install_dir="$(realpath "${install_dir}")"
tmp_dir="${install_dir}/${distro_triple}-tmp-${build_time}"

sudo="sudo -S"

if [[ ${usage} ]]; then
	usage
	trap - EXIT
	exit 0
fi

if [[ ! ${target_arch} ]]; then
	echo "${script_name}: ERROR: Must provide --arch option." >&2
	usage
	exit 1
fi

check_target_arch "${target_arch}"

set_qemu_args

if ! test -x "$(command -v ${qemu_exe})"; then
	echo "${script_name}: ERROR: Please install '${qemu_exe}'." >&2
	exit 1
fi

if [[ ${install_distro} ]]; then
	distro="${install_distro%%-*}"
	release="${install_distro#*-}"

	mkdir -p "${tmp_dir}"

	${target_arch}_installer_run "${install_dir}" "${distro}" "${release}"

	trap "on_exit 'Success'" EXIT
	exit 0
fi

check_directory "${install_dir}" " <install-dir>" "usage"

${target_arch}_start_vm "${install_dir}" "${hostname}"

trap "on_exit 'Success'" EXIT
exit 0
